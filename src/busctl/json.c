/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <float.h>
#include <locale.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "json-internal.h"
#include "json.h"
#include "macro.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "path-util.h"
#include "set.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-util.h"
#include "utf8.h"

/* On some optimization level, iszero(x) is converted to (x == 0.0), and emits warning -Wfloat-equal.
 * The argument must be a floating point, i.e. one of float, double, or long double. */
#define iszero_safe(x) (fpclassify(x) == FP_ZERO)

/* To avoid x == y and triggering compile warning -Wfloat-equal. This returns false if one of the argument is
 * NaN or infinity. One of the argument must be a floating point. */
#define fp_equal(x, y) iszero_safe((x) - (y))

/* Refuse putting together variants with a larger depth than 2K by default (as a protection against overflowing stacks
 * if code processes JSON objects recursively. Note that we store the depth in an uint16_t, hence make sure this
 * remains under 2^16.
 *
 * The value first was 16k, but it was discovered to be too high on llvm/x86-64. See also:
 * https://github.com/systemd/systemd/issues/10738
 *
 * The value then was 4k, but it was discovered to be too high on s390x/aarch64. See also:
 * https://github.com/systemd/systemd/issues/14396 */

#define DEPTH_MAX (2U*1024U)
assert_cc(DEPTH_MAX <= UINT16_MAX);

typedef struct JsonSource {
        /* When we parse from a file or similar, encodes the filename, to indicate the source of a json variant */
        unsigned n_ref;
        unsigned max_line;
        unsigned max_column;
        char name[];
} JsonSource;

/* On x86-64 this whole structure should have a size of 6 * 64 bit = 48 bytes */
struct JsonVariant {
        union {
                /* We either maintain a reference counter for this variant itself, or we are embedded into an
                 * array/object, in which case only that surrounding object is ref-counted. (If 'embedded' is false,
                 * see below.) */
                unsigned n_ref;

                /* If this JsonVariant is part of an array/object, then this field points to the surrounding
                 * JSON_VARIANT_ARRAY/JSON_VARIANT_OBJECT object. (If 'embedded' is true, see below.) */
                JsonVariant *parent;
        };

        /* If this was parsed from some file or buffer, this stores where from, as well as the source line/column */
        JsonSource *source;
        unsigned line, column;

        /* The current 'depth' of the JsonVariant, i.e. how many levels of member variants this has */
        uint16_t depth;

        JsonVariantType type:8;

        /* A marker whether this variant is embedded into in array/object or not. If true, the 'parent' pointer above
         * is valid. If false, the 'n_ref' field above is valid instead. */
        bool is_embedded:1;

        /* In some conditions (for example, if this object is part of an array of strings or objects), we don't store
         * any data inline, but instead simply reference an external object and act as surrogate of it. In that case
         * this bool is set, and the external object is referenced through the .reference field below. */
        bool is_reference:1;

        /* While comparing two arrays, we use this for marking what we already have seen */
        bool is_marked:1;

        /* Erase from memory when freeing */
        bool sensitive:1;

        /* True if we know that any referenced json object is marked sensitive */
        bool recursive_sensitive:1;

        /* If this is an object the fields are strictly ordered by name */
        bool sorted:1;

        /* If in addition to this object all objects referenced by it are also ordered strictly by name */
        bool normalized:1;

        union {
                /* For simple types we store the value in-line. */
                JsonValue value;

                /* For objects and arrays we store the number of elements immediately following */
                size_t n_elements;

                /* If is_reference as indicated above is set, this is where the reference object is actually stored. */
                JsonVariant *reference;

                /* Strings are placed immediately after the structure. Note that when this is a JsonVariant
                 * embedded into an array we might encode strings up to INLINE_STRING_LENGTH characters
                 * directly inside the element, while longer strings are stored as references. When this
                 * object is not embedded into an array, but stand-alone, we allocate the right size for the
                 * whole structure, i.e. the array might be much larger than INLINE_STRING_LENGTH. */
                DECLARE_FLEX_ARRAY(char, string);
        };
};

/* Inside string arrays we have a series of JsonVariant structures one after the other. In this case, strings longer
 * than INLINE_STRING_MAX are stored as references, and all shorter ones inline. (This means — on x86-64 — strings up
 * to 7 chars are stored within the array elements, and all others in separate allocations) */
#define INLINE_STRING_MAX (sizeof(JsonVariant) - offsetof(JsonVariant, string) - 1U)

/* Let's make sure this structure isn't increased in size accidentally. This check is only for our most relevant arch
 * (x86-64). */
#if defined(__x86_64__) && __SIZEOF_POINTER__ == 8
assert_cc(sizeof(JsonVariant) == 40U);
assert_cc(INLINE_STRING_MAX == 7U);
#endif

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(JsonSource, json_source, mfree);

/* There are four kind of JsonVariant* pointers:
 *
 *    1. NULL
 *    2. A 'regular' one, i.e. pointing to malloc() memory
 *    3. A 'magic' one, i.e. one of the special JSON_VARIANT_MAGIC_XYZ values, that encode a few very basic values directly in the pointer.
 *    4. A 'const string' one, i.e. a pointer to a const string.
 *
 * The four kinds of pointers can be discerned like this:
 *
 *    Detecting #1 is easy, just compare with NULL. Detecting #3 is similarly easy: all magic pointers are below
 *    _JSON_VARIANT_MAGIC_MAX (which is pretty low, within the first memory page, which is special on Linux and other
 *    OSes, as it is a faulting page). In order to discern #2 and #4 we check the lowest bit. If it's off it's #2,
 *    otherwise #4. This makes use of the fact that malloc() will return "maximum aligned" memory, which definitely
 *    means the pointer is even. This means we can use the uneven pointers to reference static strings, as long as we
 *    make sure that all static strings used like this are aligned to 2 (or higher), and that we mask the bit on
 *    access. The JSON_VARIANT_STRING_CONST() macro encodes strings as JsonVariant* pointers, with the bit set. */

static bool json_variant_is_magic(const JsonVariant *v) {
        if (!v)
                return false;

        return v < _JSON_VARIANT_MAGIC_MAX;
}

static bool json_variant_is_const_string(const JsonVariant *v) {

        if (v < _JSON_VARIANT_MAGIC_MAX)
                return false;

        /* A proper JsonVariant is aligned to whatever malloc() aligns things too, which is definitely not uneven. We
         * hence use all uneven pointers as indicators for const strings. */

        return (((uintptr_t) v) & 1) != 0;
}

static bool json_variant_is_regular(const JsonVariant *v) {

        if (v < _JSON_VARIANT_MAGIC_MAX)
                return false;

        return (((uintptr_t) v) & 1) == 0;
}

static JsonVariant *json_variant_dereference(JsonVariant *v) {

        /* Recursively dereference variants that are references to other variants */

        if (!v)
                return NULL;

        if (!json_variant_is_regular(v))
                return v;

        if (!v->is_reference)
                return v;

        return json_variant_dereference(v->reference);
}

static uint16_t json_variant_depth(JsonVariant *v) {

        v = json_variant_dereference(v);
        if (!v)
                return 0;

        if (!json_variant_is_regular(v))
                return 0;

        return v->depth;
}

static JsonVariant *json_variant_formalize(JsonVariant *v) {

        /* Converts json variant pointers to their normalized form, i.e. fully dereferenced and wherever
         * possible converted to the "magic" version if there is one */

        if (!v)
                return NULL;

        v = json_variant_dereference(v);

        switch (json_variant_type(v)) {

        case JSON_VARIANT_BOOLEAN:
                return json_variant_boolean(v) ? JSON_VARIANT_MAGIC_TRUE : JSON_VARIANT_MAGIC_FALSE;

        case JSON_VARIANT_NULL:
                return JSON_VARIANT_MAGIC_NULL;

        case JSON_VARIANT_INTEGER:
                return json_variant_integer(v) == 0 ? JSON_VARIANT_MAGIC_ZERO_INTEGER : v;

        case JSON_VARIANT_UNSIGNED:
                return json_variant_unsigned(v) == 0 ? JSON_VARIANT_MAGIC_ZERO_UNSIGNED : v;

        case JSON_VARIANT_REAL:
                return iszero_safe(json_variant_real(v)) ? JSON_VARIANT_MAGIC_ZERO_REAL : v;

        case JSON_VARIANT_STRING:
                return isempty(json_variant_string(v)) ? JSON_VARIANT_MAGIC_EMPTY_STRING : v;

        case JSON_VARIANT_ARRAY:
                return json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_ARRAY : v;

        case JSON_VARIANT_OBJECT:
                return json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_OBJECT : v;

        default:
                return v;
        }
}

static JsonVariant *json_variant_conservative_formalize(JsonVariant *v) {

        /* Much like json_variant_formalize(), but won't simplify if the variant has a source/line location
         * attached to it, in order not to lose context */

        if (!v)
                return NULL;

        if (!json_variant_is_regular(v))
                return v;

        if (v->source || v->line > 0 || v->column > 0)
                return v;

        return json_variant_formalize(v);
}

static int json_variant_new(JsonVariant **ret, JsonVariantType type, size_t space) {
        JsonVariant *v;

        assert_return(ret, -EINVAL);

        v = malloc0(MAX(sizeof(JsonVariant),
                        offsetof(JsonVariant, value) + space));
        if (!v)
                return -ENOMEM;

        v->n_ref = 1;
        v->type = type;

        *ret = v;
        return 0;
}

int json_variant_new_integer(JsonVariant **ret, int64_t i) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);

        if (i == 0) {
                *ret = JSON_VARIANT_MAGIC_ZERO_INTEGER;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_INTEGER, sizeof(i));
        if (r < 0)
                return r;

        v->value.integer = i;
        *ret = v;

        return 0;
}

int json_variant_new_unsigned(JsonVariant **ret, uint64_t u) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);
        if (u == 0) {
                *ret = JSON_VARIANT_MAGIC_ZERO_UNSIGNED;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_UNSIGNED, sizeof(u));
        if (r < 0)
                return r;

        v->value.unsig = u;
        *ret = v;

        return 0;
}

int json_variant_new_real(JsonVariant **ret, double d) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);

        r = fpclassify(d);
        switch (r) {
        case FP_NAN:
        case FP_INFINITE:
                /* JSON doesn't know NaN, +Infinity or -Infinity. Let's silently convert to 'null'. */
                *ret = JSON_VARIANT_MAGIC_NULL;
                return 0;

        case FP_ZERO:
                *ret = JSON_VARIANT_MAGIC_ZERO_REAL;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_REAL, sizeof(d));
        if (r < 0)
                return r;

        v->value.real = d;
        *ret = v;

        return 0;
}

int json_variant_new_boolean(JsonVariant **ret, bool b) {
        assert_return(ret, -EINVAL);

        if (b)
                *ret = JSON_VARIANT_MAGIC_TRUE;
        else
                *ret = JSON_VARIANT_MAGIC_FALSE;

        return 0;
}

int json_variant_new_null(JsonVariant **ret) {
        assert_return(ret, -EINVAL);

        *ret = JSON_VARIANT_MAGIC_NULL;
        return 0;
}

int json_variant_new_stringn(JsonVariant **ret, const char *s, size_t n) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);
        if (!s) {
                assert_return(IN_SET(n, 0, SIZE_MAX), -EINVAL);
                return json_variant_new_null(ret);
        }
        if (n == SIZE_MAX) /* determine length automatically */
                n = strlen(s);
        else if (memchr(s, 0, n)) /* don't allow embedded NUL, as we can't express that in JSON */
                return -EINVAL;
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_STRING;
                return 0;
        }

        if (!utf8_is_valid_n(s, n)) /* JSON strings must be valid UTF-8 */
                return -EUCLEAN;

        r = json_variant_new(&v, JSON_VARIANT_STRING, n + 1);
        if (r < 0)
                return r;

        memcpy(v->string, s, n);
        v->string[n] = 0;

        *ret = v;
        return 0;
}

int json_variant_new_base64(JsonVariant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;
        ssize_t k;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        k = base64mem(p, n, &s);
        if (k < 0)
                return k;

        return json_variant_new_stringn(ret, s, k);
}

int json_variant_new_base32hex(JsonVariant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        s = base32hexmem(p, n, false);
        if (!s)
                return -ENOMEM;

        return json_variant_new_string(ret, s);
}

int json_variant_new_hex(JsonVariant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        s = hexmem(p, n);
        if (!s)
                return -ENOMEM;

        return json_variant_new_stringn(ret, s, n*2);
}

int json_variant_new_id128(JsonVariant **ret, sd_id128_t id) {
        return json_variant_new_string(ret, SD_ID128_TO_STRING(id));
}

int json_variant_new_uuid(JsonVariant **ret, sd_id128_t id) {
        return json_variant_new_string(ret, SD_ID128_TO_UUID_STRING(id));
}

static void json_variant_set(JsonVariant *a, JsonVariant *b) {
        assert(a);

        b = json_variant_dereference(b);
        if (!b) {
                a->type = JSON_VARIANT_NULL;
                return;
        }

        a->type = json_variant_type(b);
        switch (a->type) {

        case JSON_VARIANT_INTEGER:
                a->value.integer = json_variant_integer(b);
                break;

        case JSON_VARIANT_UNSIGNED:
                a->value.unsig = json_variant_unsigned(b);
                break;

        case JSON_VARIANT_REAL:
                a->value.real = json_variant_real(b);
                break;

        case JSON_VARIANT_BOOLEAN:
                a->value.boolean = json_variant_boolean(b);
                break;

        case JSON_VARIANT_STRING: {
                const char *s;

                assert_se(s = json_variant_string(b));

                /* Short strings we can store inline */
                if (strnlen(s, INLINE_STRING_MAX+1) <= INLINE_STRING_MAX) {
                        strcpy(a->string, s);
                        break;
                }

                /* For longer strings, use a reference… */
                _fallthrough_;
        }

        case JSON_VARIANT_ARRAY:
        case JSON_VARIANT_OBJECT:
                a->is_reference = true;
                a->reference = json_variant_ref(json_variant_conservative_formalize(b));
                break;

        case JSON_VARIANT_NULL:
                break;

        default:
                assert_not_reached();
        }
}

static void json_variant_copy_source(JsonVariant *v, JsonVariant *from) {
        assert(v);

        if (!json_variant_is_regular(from))
                return;

        v->line = from->line;
        v->column = from->column;
        v->source = json_source_ref(from->source);
}

static int _json_variant_array_put_element(JsonVariant *array, JsonVariant *element) {
        assert(array);
        JsonVariant *w = array + 1 + array->n_elements;

        uint16_t d = json_variant_depth(element);
        if (d >= DEPTH_MAX) /* Refuse too deep nesting */
                return -ELNRNG;
        if (d >= array->depth)
                array->depth = d + 1;
        array->n_elements++;

        *w = (JsonVariant) {
                .is_embedded = true,
                .parent = array,
        };

        json_variant_set(w, element);
        json_variant_copy_source(w, element);

        if (!json_variant_is_normalized(element))
                array->normalized = false;

        return 0;
}

int json_variant_new_array(JsonVariant **ret, JsonVariant **array, size_t n) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }
        assert_return(array, -EINVAL);

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_ARRAY,
                .normalized = true,
        };

        while (v->n_elements < n) {
                r = _json_variant_array_put_element(v, array[v->n_elements]);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int json_variant_new_array_bytes(JsonVariant **ret, const void *p, size_t n) {
        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }
        assert_return(p, -EINVAL);

        JsonVariant *v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_ARRAY,
                .n_elements = n,
                .depth = 1,
        };

        for (size_t i = 0; i < n; i++) {
                JsonVariant *w = v + 1 + i;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                        .type = JSON_VARIANT_UNSIGNED,
                        .value.unsig = ((const uint8_t*) p)[i],
                };
        }

        v->normalized = true;

        *ret = v;
        return 0;
}

int json_variant_new_array_strv(JsonVariant **ret, char **l) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        size_t n;
        int r;

        assert(ret);

        n = strv_length(l);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_ARRAY,
                .depth = 1,
        };

        for (v->n_elements = 0; v->n_elements < n; v->n_elements++) {
                JsonVariant *w = v + 1 + v->n_elements;
                size_t k;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                        .type = JSON_VARIANT_STRING,
                };

                k = strlen(l[v->n_elements]);

                if (k > INLINE_STRING_MAX) {
                        /* If string is too long, store it as reference. */

                        r = json_variant_new_string(&w->reference, l[v->n_elements]);
                        if (r < 0)
                                return r;

                        w->is_reference = true;
                } else {
                        if (!utf8_is_valid_n(l[v->n_elements], k)) /* JSON strings must be valid UTF-8 */
                                return -EUCLEAN;

                        memcpy(w->string, l[v->n_elements], k+1);
                }
        }

        v->normalized = true;

        *ret = TAKE_PTR(v);
        return 0;
}

int json_variant_new_object(JsonVariant **ret, JsonVariant **array, size_t n) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        const char *prev = NULL;
        bool sorted = true, normalized = true;

        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_OBJECT;
                return 0;
        }
        assert_return(array, -EINVAL);
        assert_return(n % 2 == 0, -EINVAL);

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_OBJECT,
        };

        for (v->n_elements = 0; v->n_elements < n; v->n_elements++) {
                JsonVariant *w = v + 1 + v->n_elements,
                            *c = array[v->n_elements];
                uint16_t d;

                if ((v->n_elements & 1) == 0) {
                        const char *k;

                        if (!json_variant_is_string(c))
                                return -EINVAL; /* Every second one needs to be a string, as it is the key name */

                        assert_se(k = json_variant_string(c));

                        if (prev && strcmp(k, prev) <= 0)
                                sorted = normalized = false;

                        prev = k;
                } else if (!json_variant_is_normalized(c))
                        normalized = false;

                d = json_variant_depth(c);
                if (d >= DEPTH_MAX) /* Refuse too deep nesting */
                        return -ELNRNG;
                if (d >= v->depth)
                        v->depth = d + 1;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                };

                json_variant_set(w, c);
                json_variant_copy_source(w, c);
        }

        v->normalized = normalized;
        v->sorted = sorted;

        *ret = TAKE_PTR(v);
        return 0;
}

static size_t json_variant_size(JsonVariant* v) {
        if (!json_variant_is_regular(v))
                return 0;

        if (v->is_reference)
                return offsetof(JsonVariant, reference) + sizeof(JsonVariant*);

        switch (v->type) {

        case JSON_VARIANT_STRING:
                return offsetof(JsonVariant, string) + strlen(v->string) + 1;

        case JSON_VARIANT_REAL:
                return offsetof(JsonVariant, value) + sizeof(double);

        case JSON_VARIANT_UNSIGNED:
                return offsetof(JsonVariant, value) + sizeof(uint64_t);

        case JSON_VARIANT_INTEGER:
                return offsetof(JsonVariant, value) + sizeof(int64_t);

        case JSON_VARIANT_BOOLEAN:
                return offsetof(JsonVariant, value) + sizeof(bool);

        case JSON_VARIANT_ARRAY:
        case JSON_VARIANT_OBJECT:
                return offsetof(JsonVariant, n_elements) + sizeof(size_t);

        case JSON_VARIANT_NULL:
                return offsetof(JsonVariant, value);

        default:
                assert_not_reached();
        }
}

static void json_variant_free_inner(JsonVariant *v, bool force_sensitive) {
        bool sensitive;

        assert(v);

        if (!json_variant_is_regular(v))
                return;

        json_source_unref(v->source);

        sensitive = v->sensitive || force_sensitive;

        if (v->is_reference) {
                if (sensitive)
                        json_variant_sensitive(v->reference);

                json_variant_unref(v->reference);
                return;
        }

        if (IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                for (size_t i = 0; i < v->n_elements; i++)
                        json_variant_free_inner(v + 1 + i, sensitive);

        if (sensitive)
                explicit_bzero_safe(v, json_variant_size(v));
}

static unsigned json_variant_n_ref(const JsonVariant *v) {
        /* Return the number of references to v.
         * 0  => NULL or not a regular object or embedded.
         * >0 => number of references
         */

        if (!v || !json_variant_is_regular(v) || v->is_embedded)
                return 0;

        assert(v->n_ref > 0);
        return v->n_ref;
}

JsonVariant *json_variant_ref(JsonVariant *v) {
        if (!v)
                return NULL;
        if (!json_variant_is_regular(v))
                return v;

        if (v->is_embedded)
                json_variant_ref(v->parent); /* ref the compounding variant instead */
        else {
                assert(v->n_ref > 0);
                v->n_ref++;
        }

        return v;
}

JsonVariant *json_variant_unref(JsonVariant *v) {
        if (!v)
                return NULL;
        if (!json_variant_is_regular(v))
                return NULL;

        if (v->is_embedded)
                json_variant_unref(v->parent);
        else {
                assert(v->n_ref > 0);
                v->n_ref--;

                if (v->n_ref == 0) {
                        json_variant_free_inner(v, false);
                        free(v);
                }
        }

        return NULL;
}

void json_variant_unref_many(JsonVariant **array, size_t n) {
        assert(array || n == 0);

        for (size_t i = 0; i < n; i++)
                json_variant_unref(array[i]);

        free(array);
}

const char *json_variant_string(JsonVariant *v) {
        if (!v)
                return NULL;
        if (v == JSON_VARIANT_MAGIC_EMPTY_STRING)
                return "";
        if (json_variant_is_magic(v))
                goto mismatch;
        if (json_variant_is_const_string(v)) {
                uintptr_t p = (uintptr_t) v;

                assert((p & 1) != 0);
                return (const char*) (p ^ 1U);
        }

        if (v->is_reference)
                return json_variant_string(v->reference);
        if (v->type != JSON_VARIANT_STRING)
                goto mismatch;

        return v->string;

mismatch:
        log_debug("Non-string JSON variant requested as string, returning NULL.");
        return NULL;
}

bool json_variant_boolean(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_TRUE)
                return true;
        if (v == JSON_VARIANT_MAGIC_FALSE)
                return false;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->type != JSON_VARIANT_BOOLEAN)
                goto mismatch;
        if (v->is_reference)
                return json_variant_boolean(v->reference);

        return v->value.boolean;

mismatch:
        log_debug("Non-boolean JSON variant requested as boolean, returning false.");
        return false;
}

int64_t json_variant_integer(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_integer(v->reference);

        switch (v->type) {

        case JSON_VARIANT_INTEGER:
                return v->value.integer;

        case JSON_VARIANT_UNSIGNED:
                if (v->value.unsig <= INT64_MAX)
                        return (int64_t) v->value.unsig;

                log_debug("Unsigned integer %" PRIu64 " requested as signed integer and out of range, returning 0.", v->value.unsig);
                return 0;

        case JSON_VARIANT_REAL: {
                int64_t converted;

                converted = (int64_t) v->value.real;

                if (fp_equal((double) converted, v->value.real))
                        return converted;

                log_debug("Real %g requested as integer, and cannot be converted losslessly, returning 0.", v->value.real);
                return 0;
        }

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as integer, returning 0.");
        return 0;
}

uint64_t json_variant_unsigned(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_integer(v->reference);

        switch (v->type) {

        case JSON_VARIANT_INTEGER:
                if (v->value.integer >= 0)
                        return (uint64_t) v->value.integer;

                log_debug("Signed integer %" PRIi64 " requested as unsigned integer and out of range, returning 0.", v->value.integer);
                return 0;

        case JSON_VARIANT_UNSIGNED:
                return v->value.unsig;

        case JSON_VARIANT_REAL: {
                uint64_t converted;

                converted = (uint64_t) v->value.real;

                if (fp_equal((double) converted, v->value.real))
                        return converted;

                log_debug("Real %g requested as unsigned integer, and cannot be converted losslessly, returning 0.", v->value.real);
                return 0;
        }

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as unsigned, returning 0.");
        return 0;
}

double json_variant_real(JsonVariant *v) {
        if (!v)
                return 0.0;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0.0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_real(v->reference);

        switch (v->type) {

        case JSON_VARIANT_REAL:
                return v->value.real;

        case JSON_VARIANT_INTEGER: {
                double converted = (double) v->value.integer;

                if ((int64_t) converted == v->value.integer)
                        return converted;

                log_debug("Signed integer %" PRIi64 " requested as real, and cannot be converted losslessly, returning 0.", v->value.integer);
                return 0.0;
        }

        case JSON_VARIANT_UNSIGNED: {
                double converted = (double) v->value.unsig;

                if ((uint64_t) converted == v->value.unsig)
                        return converted;

                log_debug("Unsigned integer %" PRIu64 " requested as real, and cannot be converted losslessly, returning 0.", v->value.unsig);
                return 0.0;
        }

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as integer, returning 0.");
        return 0.0;
}

bool json_variant_is_negative(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return false;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_is_negative(v->reference);

        /* This function is useful as checking whether numbers are negative is pretty complex since we have three types
         * of numbers. And some JSON code (OCI for example) uses negative numbers to mark "not defined" numeric
         * values. */

        switch (v->type) {

        case JSON_VARIANT_REAL:
                return v->value.real < 0;

        case JSON_VARIANT_INTEGER:
                return v->value.integer < 0;

        case JSON_VARIANT_UNSIGNED:
                return false;

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant tested for negativity, returning false.");
        return false;
}

bool json_variant_is_blank_object(JsonVariant *v) {
        /* Returns true if the specified object is null or empty */
        return !v ||
                json_variant_is_null(v) ||
                (json_variant_is_object(v) && json_variant_elements(v) == 0);
}

bool json_variant_is_blank_array(JsonVariant *v) {
        return !v ||
                json_variant_is_null(v) ||
                (json_variant_is_array(v) && json_variant_elements(v) == 0);
}

JsonVariantType json_variant_type(JsonVariant *v) {

        if (!v)
                return _JSON_VARIANT_TYPE_INVALID;

        if (json_variant_is_const_string(v))
                return JSON_VARIANT_STRING;

        if (v == JSON_VARIANT_MAGIC_TRUE || v == JSON_VARIANT_MAGIC_FALSE)
                return JSON_VARIANT_BOOLEAN;

        if (v == JSON_VARIANT_MAGIC_NULL)
                return JSON_VARIANT_NULL;

        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER)
                return JSON_VARIANT_INTEGER;

        if (v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED)
                return JSON_VARIANT_UNSIGNED;

        if (v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return JSON_VARIANT_REAL;

        if (v == JSON_VARIANT_MAGIC_EMPTY_STRING)
                return JSON_VARIANT_STRING;

        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY)
                return JSON_VARIANT_ARRAY;

        if (v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return JSON_VARIANT_OBJECT;

        return v->type;
}

_function_no_sanitize_float_cast_overflow_
bool json_variant_has_type(JsonVariant *v, JsonVariantType type) {
        JsonVariantType rt;

        /* Note: we turn off ubsan float cast overflow detection for this function, since it would complain
         * about our float casts but we do them explicitly to detect conversion errors. */

        v = json_variant_dereference(v);
        if (!v)
                return false;

        rt = json_variant_type(v);
        if (rt == type)
                return true;

        /* If it's a const string, then it only can be a string, and if it is not, it's not */
        if (json_variant_is_const_string(v))
                return false;

        /* All three magic zeroes qualify as integer, unsigned and as real */
        if ((v == JSON_VARIANT_MAGIC_ZERO_INTEGER || v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED || v == JSON_VARIANT_MAGIC_ZERO_REAL) &&
            IN_SET(type, JSON_VARIANT_INTEGER, JSON_VARIANT_UNSIGNED, JSON_VARIANT_REAL, JSON_VARIANT_NUMBER))
                return true;

        /* All other magic variant types are only equal to themselves */
        if (json_variant_is_magic(v))
                return false;

        /* Handle the "number" pseudo type */
        if (type == JSON_VARIANT_NUMBER)
                return IN_SET(rt, JSON_VARIANT_INTEGER, JSON_VARIANT_UNSIGNED, JSON_VARIANT_REAL);

        /* Integer conversions are OK in many cases */
        if (rt == JSON_VARIANT_INTEGER && type == JSON_VARIANT_UNSIGNED)
                return v->value.integer >= 0;
        if (rt == JSON_VARIANT_UNSIGNED && type == JSON_VARIANT_INTEGER)
                return v->value.unsig <= INT64_MAX;

        /* Any integer that can be converted lossley to a real and back may also be considered a real */
        if (rt == JSON_VARIANT_INTEGER && type == JSON_VARIANT_REAL)
                return (int64_t) (double) v->value.integer == v->value.integer;
        if (rt == JSON_VARIANT_UNSIGNED && type == JSON_VARIANT_REAL)
                return (uint64_t) (double) v->value.unsig == v->value.unsig;

        /* Any real that can be converted losslessly to an integer and back may also be considered an integer */
        if (rt == JSON_VARIANT_REAL && type == JSON_VARIANT_INTEGER)
                return fp_equal((double) (int64_t) v->value.real, v->value.real);
        if (rt == JSON_VARIANT_REAL && type == JSON_VARIANT_UNSIGNED)
                return fp_equal((double) (uint64_t) v->value.real, v->value.real);

        return false;
}

size_t json_variant_elements(JsonVariant *v) {
        if (!v)
                return 0;
        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY ||
            v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (!IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                goto mismatch;
        if (v->is_reference)
                return json_variant_elements(v->reference);

        return v->n_elements;

mismatch:
        log_debug("Number of elements in non-array/non-object JSON variant requested, returning 0.");
        return 0;
}

JsonVariant *json_variant_by_index(JsonVariant *v, size_t idx) {
        if (!v)
                return NULL;
        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY ||
            v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return NULL;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (!IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                goto mismatch;
        if (v->is_reference)
                return json_variant_by_index(v->reference, idx);
        if (idx >= v->n_elements)
                return NULL;

        return json_variant_conservative_formalize(v + 1 + idx);

mismatch:
        log_debug("Element in non-array/non-object JSON variant requested by index, returning NULL.");
        return NULL;
}

JsonVariant *json_variant_by_key_full(JsonVariant *v, const char *key, JsonVariant **ret_key) {
        if (!v)
                goto not_found;
        if (!key)
                goto not_found;
        if (v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                goto not_found;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->type != JSON_VARIANT_OBJECT)
                goto mismatch;
        if (v->is_reference)
                return json_variant_by_key(v->reference, key);

        if (v->sorted) {
                size_t a = 0, b = v->n_elements/2;

                /* If the variant is sorted we can use bisection to find the entry we need in O(log(n)) time */

                while (b > a) {
                        JsonVariant *p;
                        const char *f;
                        size_t i;
                        int c;

                        i = (a + b) / 2;
                        p = json_variant_dereference(v + 1 + i*2);

                        assert_se(f = json_variant_string(p));

                        c = strcmp(key, f);
                        if (c == 0) {
                                if (ret_key)
                                        *ret_key = json_variant_conservative_formalize(v + 1 + i*2);

                                return json_variant_conservative_formalize(v + 1 + i*2 + 1);
                        } else if (c < 0)
                                b = i;
                        else
                                a = i + 1;
                }

                goto not_found;
        }

        /* The variant is not sorted, hence search for the field linearly */
        for (size_t i = 0; i < v->n_elements; i += 2) {
                JsonVariant *p;

                p = json_variant_dereference(v + 1 + i);

                if (!json_variant_has_type(p, JSON_VARIANT_STRING))
                        continue;

                if (streq(json_variant_string(p), key)) {

                        if (ret_key)
                                *ret_key = json_variant_conservative_formalize(v + 1 + i);

                        return json_variant_conservative_formalize(v + 1 + i + 1);
                }
        }

not_found:
        if (ret_key)
                *ret_key = NULL;

        return NULL;

mismatch:
        log_debug("Element in non-object JSON variant requested by key, returning NULL.");
        if (ret_key)
                *ret_key = NULL;

        return NULL;
}

JsonVariant *json_variant_by_key(JsonVariant *v, const char *key) {
        return json_variant_by_key_full(v, key, NULL);
}

bool json_variant_equal(JsonVariant *a, JsonVariant *b) {
        JsonVariantType t;

        a = json_variant_formalize(a);
        b = json_variant_formalize(b);

        if (a == b)
                return true;

        t = json_variant_type(a);
        if (!json_variant_has_type(b, t))
                return false;

        switch (t) {

        case JSON_VARIANT_STRING:
                return streq(json_variant_string(a), json_variant_string(b));

        case JSON_VARIANT_INTEGER:
                return json_variant_integer(a) == json_variant_integer(b);

        case JSON_VARIANT_UNSIGNED:
                return json_variant_unsigned(a) == json_variant_unsigned(b);

        case JSON_VARIANT_REAL:
                return fp_equal(json_variant_real(a), json_variant_real(b));

        case JSON_VARIANT_BOOLEAN:
                return json_variant_boolean(a) == json_variant_boolean(b);

        case JSON_VARIANT_NULL:
                return true;

        case JSON_VARIANT_ARRAY: {
                size_t n = json_variant_elements(a);
                if (n != json_variant_elements(b))
                        return false;

                for (size_t i = 0; i < n; i++)
                        if (!json_variant_equal(json_variant_by_index(a, i), json_variant_by_index(b, i)))
                                return false;

                return true;
        }

        case JSON_VARIANT_OBJECT: {
                size_t n = json_variant_elements(a);
                if (n != json_variant_elements(b))
                        return false;

                /* Iterate through all keys in 'a' */
                for (size_t i = 0; i < n; i += 2) {
                        bool found = false;

                        /* Match them against all keys in 'b' */
                        for (size_t j = 0; j < n; j += 2) {
                                JsonVariant *key_b;

                                key_b = json_variant_by_index(b, j);

                                /* During the first iteration unmark everything */
                                if (i == 0)
                                        key_b->is_marked = false;
                                else if (key_b->is_marked) /* In later iterations if we already marked something, don't bother with it again */
                                        continue;

                                if (found)
                                        continue;

                                if (json_variant_equal(json_variant_by_index(a, i), key_b) &&
                                    json_variant_equal(json_variant_by_index(a, i+1), json_variant_by_index(b, j+1))) {
                                        /* Key and values match! */
                                        key_b->is_marked = found = true;

                                        /* In the first iteration we continue the inner loop since we want to mark
                                         * everything, otherwise exit the loop quickly after we found what we were
                                         * looking for. */
                                        if (i != 0)
                                                break;
                                }
                        }

                        if (!found)
                                return false;
                }

                return true;
        }

        default:
                assert_not_reached();
        }
}

void json_variant_sensitive(JsonVariant *v) {
        assert(v);

        /* Marks a variant as "sensitive", so that it is erased from memory when it is destroyed. This is a
         * one-way operation: as soon as it is marked this way it remains marked this way until it's
         * destroyed. A magic variant is never sensitive though, even when asked, since it's too
         * basic. Similar, const string variant are never sensitive either, after all they are included in
         * the source code as they are, which is not suitable for inclusion of secrets.
         *
         * Note that this flag has a recursive effect: when we destroy an object or array we'll propagate the
         * flag to all contained variants. And if those are then destroyed this is propagated further down,
         * and so on. */

        v = json_variant_formalize(v);
        if (!json_variant_is_regular(v))
                return;

        v->sensitive = true;
}

bool json_variant_is_sensitive(JsonVariant *v) {
        v = json_variant_formalize(v);
        if (!json_variant_is_regular(v))
                return false;

        return v->sensitive;
}

bool json_variant_is_sensitive_recursive(JsonVariant *v) {
        if (!v)
                return false;
        if (json_variant_is_sensitive(v))
                return true;
        if (!json_variant_is_regular(v))
                return false;
        if (v->recursive_sensitive) /* Already checked this before */
                return true;
        if (!IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                return false;
        if (v->is_reference) {
                if (!json_variant_is_sensitive_recursive(v->reference))
                        return false;

                return (v->recursive_sensitive = true);
        }

        for (size_t i = 0; i < json_variant_elements(v); i++)
                if (json_variant_is_sensitive_recursive(json_variant_by_index(v, i)))
                        return (v->recursive_sensitive = true);

        /* Note: we only cache the result here in case true, since we allow all elements down the tree to
         * have their sensitive flag toggled later on (but never off) */
        return false;
}

static void json_variant_propagate_sensitive(JsonVariant *from, JsonVariant *to) {
        if (json_variant_is_sensitive(from))
                json_variant_sensitive(to);
}

int json_variant_get_source(JsonVariant *v, const char **ret_source, unsigned *ret_line, unsigned *ret_column) {
        assert_return(v, -EINVAL);

        if (ret_source)
                *ret_source = json_variant_is_regular(v) && v->source ? v->source->name : NULL;

        if (ret_line)
                *ret_line = json_variant_is_regular(v) ? v->line : 0;

        if (ret_column)
                *ret_column = json_variant_is_regular(v) ? v->column : 0;

        return 0;
}

static int print_source(FILE *f, JsonVariant *v, JsonFormatFlags flags, bool whitespace) {
        size_t w, k;

        if (!FLAGS_SET(flags, JSON_FORMAT_SOURCE|JSON_FORMAT_PRETTY))
                return 0;

        if (!json_variant_is_regular(v))
                return 0;

        if (!v->source && v->line == 0 && v->column == 0)
                return 0;

        /* The max width we need to format the line numbers for this source file */
        w = (v->source && v->source->max_line > 0) ?
                DECIMAL_STR_WIDTH(v->source->max_line) :
                DECIMAL_STR_MAX(unsigned)-1;
        k = (v->source && v->source->max_column > 0) ?
                DECIMAL_STR_WIDTH(v->source->max_column) :
                DECIMAL_STR_MAX(unsigned) -1;

        if (whitespace) {
                size_t n = 1 + (v->source ? strlen(v->source->name) : 0) +
                               ((v->source && (v->line > 0 || v->column > 0)) ? 1 : 0) +
                               (v->line > 0 ? w : 0) +
                               (((v->source || v->line > 0) && v->column > 0) ? 1 : 0) +
                               (v->column > 0 ? k : 0) +
                               2;

                for (size_t i = 0; i < n; i++)
                        fputc(' ', f);
        } else {
                fputc('[', f);

                if (v->source)
                        fputs(v->source->name, f);
                if (v->source && (v->line > 0 || v->column > 0))
                        fputc(':', f);
                if (v->line > 0)
                        fprintf(f, "%*u", (int) w, v->line);
                if ((v->source || v->line > 0) || v->column > 0)
                        fputc(':', f);
                if (v->column > 0)
                        fprintf(f, "%*u", (int) k, v->column);

                fputc(']', f);
                fputc(' ', f);
        }

        return 0;
}

static void json_format_string(FILE *f, const char *q, JsonFormatFlags flags) {
        assert(q);

        fputc('"', f);

        for (; *q; q++)
                switch (*q) {
                case '"':
                        fputs("\\\"", f);
                        break;

                case '\\':
                        fputs("\\\\", f);
                        break;

                case '\b':
                        fputs("\\b", f);
                        break;

                case '\f':
                        fputs("\\f", f);
                        break;

                case '\n':
                        fputs("\\n", f);
                        break;

                case '\r':
                        fputs("\\r", f);
                        break;

                case '\t':
                        fputs("\\t", f);
                        break;

                default:
                        if ((signed char) *q >= 0 && *q < ' ')
                                fprintf(f, "\\u%04x", (unsigned) *q);
                        else
                                fputc(*q, f);
                        break;
                }

        fputc('"', f);
}

static int json_format(FILE *f, JsonVariant *v, JsonFormatFlags flags, const char *prefix) {
        int r;

        assert(f);
        assert(v);

        if (FLAGS_SET(flags, JSON_FORMAT_CENSOR_SENSITIVE) && json_variant_is_sensitive(v)) {
                fputs("\"<sensitive data>\"", f);
                return 0;
        }

        switch (json_variant_type(v)) {

        case JSON_VARIANT_REAL: {
                locale_t loc, old_loc;

                loc = newlocale(LC_NUMERIC_MASK, "C", (locale_t) 0);
                if (loc == (locale_t) 0)
                        return -errno;

                old_loc = uselocale(loc);
                fprintf(f, "%.*e", DECIMAL_DIG, json_variant_real(v));
                uselocale(old_loc);

                freelocale(loc);
                break;
        }

        case JSON_VARIANT_INTEGER:
                fprintf(f, "%" PRIdMAX, json_variant_integer(v));
                break;

        case JSON_VARIANT_UNSIGNED:
                fprintf(f, "%" PRIuMAX, json_variant_unsigned(v));
                break;

        case JSON_VARIANT_BOOLEAN:
                if (json_variant_boolean(v))
                        fputs("true", f);
                else
                        fputs("false", f);

                break;

        case JSON_VARIANT_NULL:
                fputs("null", f);
                break;

        case JSON_VARIANT_STRING:
                json_format_string(f, json_variant_string(v), flags);
                break;

        case JSON_VARIANT_ARRAY: {
                size_t n = json_variant_elements(v);
                if (n == 0)
                        fputs("[]", f);
                else {
                        _cleanup_free_ char *joined = NULL;
                        const char *prefix2;

                        if (flags & JSON_FORMAT_PRETTY) {
                                joined = strjoin(strempty(prefix), "\t");
                                if (!joined)
                                        return -ENOMEM;

                                prefix2 = joined;
                                fputs("[\n", f);
                        } else {
                                prefix2 = strempty(prefix);
                                fputc('[', f);
                        }

                        for (size_t i = 0; i < n; i++) {
                                JsonVariant *e;

                                assert_se(e = json_variant_by_index(v, i));

                                if (i > 0) {
                                        if (flags & JSON_FORMAT_PRETTY)
                                                fputs(",\n", f);
                                        else
                                                fputc(',', f);
                                }

                                if (flags & JSON_FORMAT_PRETTY) {
                                        print_source(f, e, flags, false);
                                        fputs(prefix2, f);
                                }

                                r = json_format(f, e, flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                print_source(f, v, flags, true);
                                fputs(strempty(prefix), f);
                        }

                        fputc(']', f);
                }
                break;
        }

        case JSON_VARIANT_OBJECT: {
                size_t n = json_variant_elements(v);
                if (n == 0)
                        fputs("{}", f);
                else {
                        _cleanup_free_ char *joined = NULL;
                        const char *prefix2;

                        if (flags & JSON_FORMAT_PRETTY) {
                                joined = strjoin(strempty(prefix), "\t");
                                if (!joined)
                                        return -ENOMEM;

                                prefix2 = joined;
                                fputs("{\n", f);
                        } else {
                                prefix2 = strempty(prefix);
                                fputc('{', f);
                        }

                        for (size_t i = 0; i < n; i += 2) {
                                JsonVariant *e;

                                e = json_variant_by_index(v, i);

                                if (i > 0) {
                                        if (flags & JSON_FORMAT_PRETTY)
                                                fputs(",\n", f);
                                        else
                                                fputc(',', f);
                                }

                                if (flags & JSON_FORMAT_PRETTY) {
                                        print_source(f, e, flags, false);
                                        fputs(prefix2, f);
                                }

                                r = json_format(f, e, flags, prefix2);
                                if (r < 0)
                                        return r;

                                fputs(flags & JSON_FORMAT_PRETTY ? " : " : ":", f);

                                r = json_format(f, json_variant_by_index(v, i+1), flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                print_source(f, v, flags, true);
                                fputs(strempty(prefix), f);
                        }

                        fputc('}', f);
                }
                break;
        }

        default:
                assert_not_reached();
        }

        return 0;
}

int json_variant_format(JsonVariant *v, JsonFormatFlags flags, char **ret) {
        _cleanup_(memstream_done) MemStream m = {};
        size_t sz;
        FILE *f;
        int r;

        /* Returns the length of the generated string (without the terminating NUL),
         * or negative on error. */

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        if (flags & JSON_FORMAT_OFF)
                return -ENOEXEC;

        f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        r = json_variant_dump(v, flags, f, NULL);
        if (r < 0)
                return r;

        r = memstream_finalize(&m, ret, &sz);
        if (r < 0)
                return r;

        return sz;
}

int json_variant_dump(JsonVariant *v, JsonFormatFlags flags, FILE *f, const char *prefix) {
        if (!v) {
                if (flags & JSON_FORMAT_EMPTY_ARRAY)
                        v = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                else
                        return 0;
        }

        if (!f)
                f = stdout;

        print_source(f, v, flags, false);

        if (((flags & (JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_PRETTY)) == JSON_FORMAT_PRETTY_AUTO))
                flags |= isatty(STDOUT_FILENO) > 0 ? JSON_FORMAT_PRETTY : JSON_FORMAT_NEWLINE;

        if (flags & JSON_FORMAT_SSE)
                fputs("data: ", f);
        if (flags & JSON_FORMAT_SEQ)
                fputc('\x1e', f); /* ASCII Record Separator */

        json_format(f, v, flags, prefix);

        if (flags & (JSON_FORMAT_PRETTY|JSON_FORMAT_SEQ|JSON_FORMAT_SSE|JSON_FORMAT_NEWLINE))
                fputc('\n', f);
        if (flags & JSON_FORMAT_SSE)
                fputc('\n', f); /* In case of SSE add a second newline */

        if (flags & JSON_FORMAT_FLUSH)
                return fflush_and_check(f);
        return 0;
}

int json_variant_filter(JsonVariant **v, char **to_remove) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        _cleanup_free_ JsonVariant **array = NULL;
        size_t n = 0, k = 0;
        int r;

        assert(v);

        if (json_variant_is_blank_object(*v))
                return 0;
        if (!json_variant_is_object(*v))
                return -EINVAL;

        if (strv_isempty(to_remove))
                return 0;

        for (size_t i = 0; i < json_variant_elements(*v); i += 2) {
                JsonVariant *p;

                p = json_variant_by_index(*v, i);
                if (!json_variant_has_type(p, JSON_VARIANT_STRING))
                        return -EINVAL;

                if (strv_contains(to_remove, json_variant_string(p))) {
                        if (!array) {
                                array = new(JsonVariant*, json_variant_elements(*v) - 2);
                                if (!array)
                                        return -ENOMEM;

                                for (k = 0; k < i; k++)
                                        array[k] = json_variant_by_index(*v, k);
                        }

                        n++;
                } else if (array) {
                        array[k++] = p;
                        array[k++] = json_variant_by_index(*v, i + 1);
                }
        }

        if (n == 0)
                return 0;

        r = json_variant_new_object(&w, array, k);
        if (r < 0)
                return r;

        json_variant_propagate_sensitive(*v, w);
        JSON_VARIANT_REPLACE(*v, TAKE_PTR(w));

        return (int) n;
}

int json_variant_set_field(JsonVariant **v, const char *field, JsonVariant *value) {
        _cleanup_(json_variant_unrefp) JsonVariant *field_variant = NULL, *w = NULL;
        _cleanup_free_ JsonVariant **array = NULL;
        size_t k = 0;
        int r;

        assert(v);
        assert(field);

        if (json_variant_is_blank_object(*v)) {
                array = new(JsonVariant*, 2);
                if (!array)
                        return -ENOMEM;

        } else {
                if (!json_variant_is_object(*v))
                        return -EINVAL;

                for (size_t i = 0; i < json_variant_elements(*v); i += 2) {
                        JsonVariant *p;

                        p = json_variant_by_index(*v, i);
                        if (!json_variant_is_string(p))
                                return -EINVAL;

                        if (streq(json_variant_string(p), field)) {

                                if (!array) {
                                        array = new(JsonVariant*, json_variant_elements(*v));
                                        if (!array)
                                                return -ENOMEM;

                                        for (k = 0; k < i; k++)
                                                array[k] = json_variant_by_index(*v, k);
                                }

                        } else if (array) {
                                array[k++] = p;
                                array[k++] = json_variant_by_index(*v, i + 1);
                        }
                }

                if (!array) {
                        array = new(JsonVariant*, json_variant_elements(*v) + 2);
                        if (!array)
                                return -ENOMEM;

                        for (k = 0; k < json_variant_elements(*v); k++)
                                array[k] = json_variant_by_index(*v, k);
                }
        }

        r = json_variant_new_string(&field_variant, field);
        if (r < 0)
                return r;

        array[k++] = field_variant;
        array[k++] = value;

        r = json_variant_new_object(&w, array, k);
        if (r < 0)
                return r;

        json_variant_propagate_sensitive(*v, w);
        JSON_VARIANT_REPLACE(*v, TAKE_PTR(w));

        return 1;
}

int json_variant_set_fieldb(JsonVariant **v, const char *field, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        va_list ap;
        int r;

        va_start(ap, field);
        r = json_buildv(&w, ap);
        va_end(ap);
        if (r < 0)
                return r;

        return json_variant_set_field(v, field, w);
}

int json_variant_set_field_string(JsonVariant **v, const char *field, const char *value) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_variant_new_string(&m, value);
        if (r < 0)
                return r;

        return json_variant_set_field(v, field, m);
}

int json_variant_set_field_integer(JsonVariant **v, const char *field, int64_t i) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_variant_new_integer(&m, i);
        if (r < 0)
                return r;

        return json_variant_set_field(v, field, m);
}

int json_variant_set_field_unsigned(JsonVariant **v, const char *field, uint64_t u) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_variant_new_unsigned(&m, u);
        if (r < 0)
                return r;

        return json_variant_set_field(v, field, m);
}

int json_variant_set_field_boolean(JsonVariant **v, const char *field, bool b) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_variant_new_boolean(&m, b);
        if (r < 0)
                return r;

        return json_variant_set_field(v, field, m);
}

int json_variant_set_field_strv(JsonVariant **v, const char *field, char **l) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_variant_new_array_strv(&m, l);
        if (r < 0)
                return r;

        return json_variant_set_field(v, field, m);
}

int json_variant_merge_object(JsonVariant **v, JsonVariant *m) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        _cleanup_free_ JsonVariant **array = NULL;
        size_t v_elements, m_elements, k;
        bool v_blank, m_blank;
        int r;

        m = json_variant_dereference(m);

        v_blank = json_variant_is_blank_object(*v);
        m_blank = json_variant_is_blank_object(m);

        if (!v_blank && !json_variant_is_object(*v))
                return -EINVAL;
        if (!m_blank && !json_variant_is_object(m))
                return -EINVAL;

        if (m_blank)
                return 0; /* nothing to do */

        if (v_blank) {
                JSON_VARIANT_REPLACE(*v, json_variant_ref(m));
                return 1;
        }

        v_elements = json_variant_elements(*v);
        m_elements = json_variant_elements(m);
        if (v_elements > SIZE_MAX - m_elements) /* overflow check */
                return -ENOMEM;

        array = new(JsonVariant*, v_elements + m_elements);
        if (!array)
                return -ENOMEM;

        k = 0;
        for (size_t i = 0; i < v_elements; i += 2) {
                JsonVariant *u;

                u = json_variant_by_index(*v, i);
                if (!json_variant_is_string(u))
                        return -EINVAL;

                if (json_variant_by_key(m, json_variant_string(u)))
                        continue; /* skip if exists in second variant */

                array[k++] = u;
                array[k++] = json_variant_by_index(*v, i + 1);
        }

        for (size_t i = 0; i < m_elements; i++)
                array[k++] = json_variant_by_index(m, i);

        r = json_variant_new_object(&w, array, k);
        if (r < 0)
                return r;

        json_variant_propagate_sensitive(*v, w);
        json_variant_propagate_sensitive(m, w);
        JSON_VARIANT_REPLACE(*v, TAKE_PTR(w));

        return 1;
}

int json_variant_merge_objectb(JsonVariant **v, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        va_list ap;
        int r;

        va_start(ap, v);
        r = json_buildv(&w, ap);
        va_end(ap);
        if (r < 0)
                return r;

        return json_variant_merge_object(v, w);
}

int json_variant_append_array(JsonVariant **v, JsonVariant *element) {
        _cleanup_(json_variant_unrefp) JsonVariant *nv = NULL;
        bool blank;
        int r;

        assert(v);
        assert(element);

        if (!*v || json_variant_is_null(*v))
                blank = true;
        else if (json_variant_is_array(*v))
                blank = json_variant_elements(*v) == 0;
        else
                return -EINVAL;

        if (blank) {
                r = json_variant_new_array(&nv, (JsonVariant*[]) { element }, 1);
                if (r < 0)
                        return r;
        } else if (json_variant_n_ref(*v) == 1) {
                /* Let's bump the reference count on element. We can't do the realloc if we're appending *v
                 * to itself, or one of the objects embedded in *v to *v. If the reference count grows, we
                 * need to fall back to the other method below. */

                _unused_ _cleanup_(json_variant_unrefp) JsonVariant *dummy = json_variant_ref(element);
                if (json_variant_n_ref(*v) == 1) {
                        /* We hold the only reference. Let's mutate the object. */
                        size_t size = json_variant_elements(*v);
                        void *old = *v;

                        if (!GREEDY_REALLOC(*v, size + 1 + 1))
                                return -ENOMEM;

                        if (old != *v)
                                /* Readjust the parent pointers to the new address */
                                for (size_t i = 1; i < size; i++)
                                        (*v)[1 + i].parent = *v;

                        return _json_variant_array_put_element(*v, element);
                }
        }

        if (!blank) {
                size_t size = json_variant_elements(*v);

                _cleanup_free_ JsonVariant **array = new(JsonVariant*, size + 1);
                if (!array)
                        return -ENOMEM;

                for (size_t i = 0; i < size; i++)
                        array[i] = json_variant_by_index(*v, i);

                array[size] = element;

                r = json_variant_new_array(&nv, array, size + 1);
                if (r < 0)
                        return r;
        }

        json_variant_propagate_sensitive(*v, nv);
        JSON_VARIANT_REPLACE(*v, TAKE_PTR(nv));

        return 0;
}

int json_variant_append_arrayb(JsonVariant **v, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        va_list ap;
        int r;

        va_start(ap, v);
        r = json_buildv(&w, ap);
        va_end(ap);
        if (r < 0)
                return r;

        return json_variant_append_array(v, w);
}

JsonVariant *json_variant_find(JsonVariant *haystack, JsonVariant *needle) {
        JsonVariant *i;

        /* Find a json object in an array. Returns NULL if not found, or if the array is not actually an array. */

        JSON_VARIANT_ARRAY_FOREACH(i, haystack)
                if (json_variant_equal(i, needle))
                        return i;

        return NULL;
}

int json_variant_append_array_nodup(JsonVariant **v, JsonVariant *element) {
        assert(v);

        if (json_variant_find(*v, element))
                return 0;

        return json_variant_append_array(v, element);
}

int json_variant_strv(JsonVariant *v, char ***ret) {
        char **l = NULL;
        bool sensitive;
        int r;

        assert(ret);

        if (!v || json_variant_is_null(v)) {
                l = new0(char*, 1);
                if (!l)
                        return -ENOMEM;

                *ret = l;
                return 0;
        }

        if (!json_variant_is_array(v))
                return -EINVAL;

        sensitive = json_variant_is_sensitive(v);

        size_t n = json_variant_elements(v);
        l = new(char*, n+1);
        if (!l)
                return -ENOMEM;

        for (size_t i = 0; i < n; i++) {
                JsonVariant *e;

                assert_se(e = json_variant_by_index(v, i));
                sensitive = sensitive || json_variant_is_sensitive(e);

                if (!json_variant_is_string(e)) {
                        l[i] = NULL;
                        r = -EINVAL;
                        goto fail;
                }

                l[i] = strdup(json_variant_string(e));
                if (!l[i]) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        l[n] = NULL;
        *ret = TAKE_PTR(l);

        return 0;

fail:
        if (sensitive)
                strv_free_erase(l);
        else
                strv_free(l);

        return r;
}

typedef enum JsonExpect {
        /* The following values are used by json_parse() */
        EXPECT_TOPLEVEL,
        EXPECT_END,
        EXPECT_OBJECT_FIRST_KEY,
        EXPECT_OBJECT_NEXT_KEY,
        EXPECT_OBJECT_COLON,
        EXPECT_OBJECT_VALUE,
        EXPECT_OBJECT_COMMA,
        EXPECT_ARRAY_FIRST_ELEMENT,
        EXPECT_ARRAY_NEXT_ELEMENT,
        EXPECT_ARRAY_COMMA,

        /* And these are used by json_build() */
        EXPECT_ARRAY_ELEMENT,
        EXPECT_OBJECT_KEY,
} JsonExpect;

typedef struct JsonStack {
        JsonExpect expect;
        JsonVariant **elements;
        size_t n_elements;
        unsigned line_before;
        unsigned column_before;
        size_t n_suppress; /* When building: if > 0, suppress this many subsequent elements. If == SIZE_MAX, suppress all subsequent elements */
} JsonStack;

static void json_stack_release(JsonStack *s) {
        assert(s);

        CLEANUP_ARRAY(s->elements, s->n_elements, json_variant_unref_many);
}

int json_buildv(JsonVariant **ret, va_list ap) {
        JsonStack *stack = NULL;
        size_t n_stack = 1;
        const char *name = NULL;
        int r;

        assert_return(ret, -EINVAL);

        if (!GREEDY_REALLOC(stack, n_stack))
                return -ENOMEM;

        stack[0] = (JsonStack) {
                .expect = EXPECT_TOPLEVEL,
        };

        for (;;) {
                _cleanup_(json_variant_unrefp) JsonVariant *add = NULL, *add_more = NULL;
                size_t n_subtract = 0; /* how much to subtract from current->n_suppress, i.e. how many elements would
                                        * have been added to the current variant */
                JsonStack *current;
                int command;

                assert(n_stack > 0);
                current = stack + n_stack - 1;

                if (current->expect == EXPECT_END)
                        goto done;

                command = va_arg(ap, int);

                switch (command) {

                case _JSON_BUILD_STRING: {
                        const char *p;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        p = va_arg(ap, const char *);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_string(&add, p);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_INTEGER: {
                        int64_t j;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        j = va_arg(ap, int64_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_integer(&add, j);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_UNSIGNED: {
                        uint64_t j;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        j = va_arg(ap, uint64_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_unsigned(&add, j);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_REAL: {
                        double d;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        d = va_arg(ap, double);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_real(&add, d);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_BOOLEAN: {
                        bool b;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        b = va_arg(ap, int);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_boolean(&add, b);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_NULL:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (current->n_suppress == 0) {
                                r = json_variant_new_null(&add);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;

                case _JSON_BUILD_VARIANT:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        /* Note that we don't care for current->n_suppress here, after all the variant is already
                         * allocated anyway... */
                        add = va_arg(ap, JsonVariant*);
                        if (!add)
                                add = JSON_VARIANT_MAGIC_NULL;
                        else
                                json_variant_ref(add);

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;

                case _JSON_BUILD_VARIANT_ARRAY: {
                        JsonVariant **array;
                        size_t n;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        array = va_arg(ap, JsonVariant**);
                        n = va_arg(ap, size_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array(&add, array, n);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_ARRAY_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_ARRAY_ELEMENT,
                                .n_suppress = current->n_suppress != 0 ? SIZE_MAX : 0, /* if we shall suppress the
                                                                                           * new array, then we should
                                                                                           * also suppress all array
                                                                                           * members */
                        };

                        break;

                case _JSON_BUILD_ARRAY_END:
                        if (current->expect != EXPECT_ARRAY_ELEMENT) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array(&add, current->elements, current->n_elements);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _JSON_BUILD_STRV: {
                        char **l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, char **);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array_strv(&add, l);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_STRV_ENV_PAIR: {
                        char **l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, char **);

                        _cleanup_strv_free_ char **el = NULL;
                        STRV_FOREACH_PAIR(x, y, l) {
                                char *n = NULL;

                                n = strjoin(*x, "=", *y);
                                if (!n) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                r = strv_consume(&el, n);
                                if (r < 0)
                                        goto finish;
                        }

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array_strv(&add, el);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_BASE64:
                case _JSON_BUILD_BASE32HEX:
                case _JSON_BUILD_HEX: {
                        const void *p;
                        size_t n;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        p = va_arg(ap, const void *);
                        n = va_arg(ap, size_t);

                        if (current->n_suppress == 0) {
                                r = command == _JSON_BUILD_BASE64    ? json_variant_new_base64(&add, p, n) :
                                    command == _JSON_BUILD_BASE32HEX ? json_variant_new_base32hex(&add, p, n) :
                                                                       json_variant_new_hex(&add, p, n);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_IOVEC_BASE64:
                case _JSON_BUILD_IOVEC_HEX: {
                        const struct iovec *iov;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        iov = va_arg(ap, const struct iovec*);

                        if (current->n_suppress == 0) {
                                if (iov)
                                        r = command == _JSON_BUILD_IOVEC_BASE64 ? json_variant_new_base64(&add, iov->iov_base, iov->iov_len) :
                                                                                  json_variant_new_hex(&add, iov->iov_base, iov->iov_len);
                                else
                                        r = json_variant_new_string(&add, "");
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_ID128:
                case _JSON_BUILD_UUID: {
                        const sd_id128_t *id;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert_se(id = va_arg(ap, sd_id128_t*));

                        if (current->n_suppress == 0) {
                                r = command == _JSON_BUILD_ID128 ?
                                        json_variant_new_id128(&add, *id) :
                                        json_variant_new_uuid(&add, *id);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_BYTE_ARRAY: {
                        const void *array;
                        size_t n;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        array = va_arg(ap, const void*);
                        n = va_arg(ap, size_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array_bytes(&add, array, n);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_CALLBACK: {
                        JsonBuildCallback cb;
                        void *userdata;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        cb = va_arg(ap, JsonBuildCallback);
                        userdata = va_arg(ap, void *);

                        if (current->n_suppress == 0) {
                                if (cb) {
                                        r = cb(&add, name, userdata);
                                        if (r < 0)
                                                goto finish;
                                }

                                if (!add)
                                        add = JSON_VARIANT_MAGIC_NULL;

                                name = NULL;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_OBJECT_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_OBJECT_KEY,
                                .n_suppress = current->n_suppress != 0 ? SIZE_MAX : 0, /* If we shall suppress the
                                                                                        * new object, then we should
                                                                                        * also suppress all object
                                                                                        * members. */
                        };

                        break;

                case _JSON_BUILD_OBJECT_END:

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_object(&add, current->elements, current->n_elements);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _JSON_BUILD_PAIR: {

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        name = va_arg(ap, const char *);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_string(&add, name);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;
                }

                case _JSON_BUILD_PAIR_CONDITION: {
                        bool b;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        b = va_arg(ap, int);
                        name = va_arg(ap, const char *);

                        if (b && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, name);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1; /* we generated one item */

                        if (!b && current->n_suppress != SIZE_MAX)
                                current->n_suppress += 2; /* Suppress this one and the next item */

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;
                }

                case _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO: {
                        const char *n;
                        uint64_t u;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        u = va_arg(ap, uint64_t);

                        if (u != 0 && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_unsigned(&add_more, u);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_FINITE_USEC: {
                        const char *n;
                        usec_t u;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        u = va_arg(ap, usec_t);

                        if (u != USEC_INFINITY && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_unsigned(&add_more, u);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_STRING_NON_EMPTY: {
                        const char *n, *s;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        s = va_arg(ap, const char *);

                        if (!isempty(s) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_string(&add_more, s);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_STRV_NON_EMPTY: {
                        const char *n;
                        char **l;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        l = va_arg(ap, char **);

                        if (!strv_isempty(l) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_array_strv(&add_more, l);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_VARIANT_NON_NULL: {
                        JsonVariant *v;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        v = va_arg(ap, JsonVariant *);

                        if (v && !json_variant_is_null(v) && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                add_more = json_variant_ref(v);
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }
                }

                /* If variants were generated, add them to our current variant, but only if we are not supposed to suppress additions */
                if (add && current->n_suppress == 0) {
                        if (!GREEDY_REALLOC(current->elements, current->n_elements + 1 + !!add_more)) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        current->elements[current->n_elements++] = TAKE_PTR(add);
                        if (add_more)
                                current->elements[current->n_elements++] = TAKE_PTR(add_more);
                }

                /* If we are supposed to suppress items, let's subtract how many items where generated from
                 * that counter. Except if the counter is SIZE_MAX, i.e. we shall suppress an infinite number
                 * of elements on this stack level */
                if (current->n_suppress != SIZE_MAX) {
                        if (current->n_suppress <= n_subtract) /* Saturated */
                                current->n_suppress = 0;
                        else
                                current->n_suppress -= n_subtract;
                }
        }

done:
        assert(n_stack == 1);
        assert(stack[0].n_elements == 1);

        *ret = json_variant_ref(stack[0].elements[0]);
        r = 0;

finish:
        for (size_t i = 0; i < n_stack; i++)
                json_stack_release(stack + i);

        free(stack);

        return r;
}

int json_build(JsonVariant **ret, ...) {
        va_list ap;
        int r;

        va_start(ap, ret);
        r = json_buildv(ret, ap);
        va_end(ap);

        return r;
}

static int json_cmp_strings(const void *x, const void *y) {
        JsonVariant *const *a = x, *const *b = y;

        if (!json_variant_is_string(*a) || !json_variant_is_string(*b))
                return CMP(*a, *b);

        return strcmp(json_variant_string(*a), json_variant_string(*b));
}

int json_variant_sort(JsonVariant **v) {
        _cleanup_free_ JsonVariant **a = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *n = NULL;
        size_t m;
        int r;

        assert(v);

        if (json_variant_is_sorted(*v))
                return 0;

        if (!json_variant_is_object(*v))
                return -EMEDIUMTYPE;

        /* Sorts they key/value pairs in an object variant */

        m = json_variant_elements(*v);
        a = new(JsonVariant*, m);
        if (!a)
                return -ENOMEM;

        for (size_t i = 0; i < m; i++)
                a[i] = json_variant_by_index(*v, i);

        qsort(a, m/2, sizeof(JsonVariant*)*2, json_cmp_strings);

        r = json_variant_new_object(&n, a, m);
        if (r < 0)
                return r;

        json_variant_propagate_sensitive(*v, n);

        if (!n->sorted) /* Check if this worked. This will fail if there are multiple identical keys used. */
                return -ENOTUNIQ;

        JSON_VARIANT_REPLACE(*v, TAKE_PTR(n));

        return 1;
}

int json_variant_normalize(JsonVariant **v) {
        _cleanup_free_ JsonVariant **a = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *n = NULL;
        size_t i, m;
        int r;

        assert(v);

        if (json_variant_is_normalized(*v))
                return 0;

        if (!json_variant_is_object(*v) && !json_variant_is_array(*v))
                return -EMEDIUMTYPE;

        /* Sorts the key/value pairs in an object variant anywhere down the tree in the specified variant */

        m = json_variant_elements(*v);
        a = new(JsonVariant*, m);
        if (!a)
                return -ENOMEM;

        for (i = 0; i < m; ) {
                a[i] = json_variant_ref(json_variant_by_index(*v, i));
                i++;

                r = json_variant_normalize(&a[i-1]);
                if (r < 0)
                        goto finish;
        }

        qsort(a, m/2, sizeof(JsonVariant*)*2, json_cmp_strings);

        if (json_variant_is_object(*v))
                r = json_variant_new_object(&n, a, m);
        else {
                assert(json_variant_is_array(*v));
                r = json_variant_new_array(&n, a, m);
        }
        if (r < 0)
                goto finish;

        json_variant_propagate_sensitive(*v, n);

        if (!n->normalized) { /* Let's see if normalization worked. It will fail if there are multiple
                               * identical keys used in the same object anywhere, or if there are floating
                               * point numbers used (see below) */
                r = -ENOTUNIQ;
                goto finish;
        }

        JSON_VARIANT_REPLACE(*v, TAKE_PTR(n));

        r = 1;

finish:
        for (size_t j = 0; j < i; j++)
                json_variant_unref(a[j]);

        return r;
}

bool json_variant_is_normalized(JsonVariant *v) {
        /* For now, let's consider anything containing numbers not expressible as integers as non-normalized.
         * That's because we cannot sensibly compare them due to accuracy issues, nor even store them if they
         * are too large. */
        if (json_variant_is_real(v) && !json_variant_is_integer(v) && !json_variant_is_unsigned(v))
                return false;

        /* The concept only applies to variants that include other variants, i.e. objects and arrays. All
         * others are normalized anyway. */
        if (!json_variant_is_object(v) && !json_variant_is_array(v))
                return true;

        /* Empty objects/arrays don't include any other variant, hence are always normalized too */
        if (json_variant_elements(v) == 0)
                return true;

        return v->normalized; /* For everything else there's an explicit boolean we maintain */
}

bool json_variant_is_sorted(JsonVariant *v) {

        /* Returns true if all key/value pairs of an object are properly sorted. Note that this only applies
         * to objects, not arrays. */

        if (!json_variant_is_object(v))
                return true;
        if (json_variant_elements(v) <= 1)
                return true;

        return v->sorted;
}

int json_variant_unbase64(JsonVariant *v, void **ret, size_t *ret_size) {
        if (!json_variant_is_string(v))
                return -EINVAL;

        return unbase64mem_full(json_variant_string(v), SIZE_MAX, /* secure= */ json_variant_is_sensitive(v), ret, ret_size);
}

int json_variant_unhex(JsonVariant *v, void **ret, size_t *ret_size) {
        if (!json_variant_is_string(v))
                return -EINVAL;

        return unhexmem_full(json_variant_string(v), SIZE_MAX, /* secure= */ json_variant_is_sensitive(v), ret, ret_size);
}

static const char* const json_variant_type_table[_JSON_VARIANT_TYPE_MAX] = {
        [JSON_VARIANT_STRING]   = "string",
        [JSON_VARIANT_INTEGER]  = "integer",
        [JSON_VARIANT_UNSIGNED] = "unsigned",
        [JSON_VARIANT_REAL]     = "real",
        [JSON_VARIANT_NUMBER]   = "number",
        [JSON_VARIANT_BOOLEAN]  = "boolean",
        [JSON_VARIANT_ARRAY]    = "array",
        [JSON_VARIANT_OBJECT]   = "object",
        [JSON_VARIANT_NULL]     = "null",
};

DEFINE_STRING_TABLE_LOOKUP(json_variant_type, JsonVariantType);
