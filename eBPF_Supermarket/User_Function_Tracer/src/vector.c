// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: jinyufeng2000@gmail.com
//
// A dynamic array similar to std::vector, but only has std::stack-like capabilities

#include "vector.h"

#include <memory.h>
#include <stdlib.h>

struct vector *vector_init(size_t element_size, vector_element_free_t free) {
  struct vector *vec = malloc(sizeof(struct vector));
  vec->size = 0;
  vec->capacity = 0;
  vec->element_size = element_size;
  vec->data = NULL;
  vec->free = free;
  return vec;
}

void vector_free(struct vector *vec) {
  if (vec) {
    if (vec->free) {
      for (size_t i = 0; i < vector_size(vec); i++) {
        vec->free(vector_get(vec, i));
      }
    }
    free(vec->data);
    free(vec);
  }
}

// assert vec != NULL
size_t vector_size(const struct vector *vec) { return vec->size; }

// assert vec != NULL
bool vector_empty(const struct vector *vec) { return !vec->size; }

// assert vec != NULL && index >= 0 && index < vec->size
void *vector_get(struct vector *vec, size_t index) {
  return vec->data + (index * vec->element_size);
}

// assert vec != NULL && index >= 0 && index < vec->size
const void *vector_const_get(const struct vector *vec, size_t index) {
  return vec->data + (index * vec->element_size);
}

// assert vec != NULL && vec->size > 0
void *vector_front(struct vector *vec) { return vector_get(vec, 0); }

// assert vec != NULL && vec->size > 0
void *vector_back(struct vector *vec) { return vector_get(vec, vector_size(vec) - 1); }

// assert vec != NULL
int vector_reserve(struct vector *vec, size_t size) {
  if (vec->capacity < size) {
    const size_t malloc_size = size * vec->element_size;
    void *realloc_data = realloc(vec->data, malloc_size);
    // when realloc_data is NULL, vec->data remains valid,
    // it needs to be freed, and cannot be overwritten
    if (!realloc_data) {
      return -1;
    }
    vec->data = realloc_data;
    vec->capacity = size;
  }
  return 0;
}

// assert vec != NULL
int vector_resize(struct vector *vec, size_t size) {
  vector_reserve(vec, size);
  vec->size = size;
  return 0;
}

/**
 * @brief double the `size`
 */
static size_t vector_size_grow(size_t size) { return !size ? 1 : size << 1; }

// assert vec != NULL && index >= 0 && index < vec->size
void vector_set(struct vector *vec, size_t index, const void *element) {
  // element does not overlap with vec->data[index]
  memcpy(vec->data + (index * vec->element_size), element, vec->element_size);
}

// assert vec != NULL
int vector_push_back(struct vector *vec, const void *element) {
  if (vec->size == vec->capacity) {
    if (vector_reserve(vec, vector_size_grow(vec->size)) == -1) {
      return -1;
    }
  }

  vector_set(vec, vec->size, element);
  ++vec->size;
  return 0;
}

// assert vec != NULL && vec->size > 0
void vector_pop_back(struct vector *vec) { --vec->size; }

// assert vec != NULL
void vector_clear(struct vector *vec) { vec->size = 0; }

// assert vec != NULL && comparator != NULL
void vector_sort(struct vector *vec, int (*comparator)(const void *, const void *)) {
  qsort(vec->data, vec->size, vec->element_size, comparator);
}

// assert vec != NULL && comparator != NULL && vec is sorted by comparator
void vector_unique(struct vector *vec, int (*comparator)(const void *, const void *)) {
  if (!vector_empty(vec)) {
    size_t j = 1;
    for (size_t i = 1; i < vector_size(vec); i++) {
      void *element = vector_get(vec, i);
      if (comparator(element, vector_const_get(vec, i - 1))) {
        if (i != j) vector_set(vec, j, element);
        ++j;
      } else if (vec->free) {
        vec->free(element);
      }
    }
    vec->size = j;
  }
}

// assert vec != NULL && comparator != NULL
void *vector_binary_search(struct vector *vec, const void *key,
                           int (*comparator)(const void *, const void *)) {
  if (!vector_empty(vec)) {
    size_t l = 0, r = vector_size(vec) - 1;
    while (l <= r) {
      size_t mid = (l + r) >> 1;
      void *element = vector_get(vec, mid);
      int cmp = comparator(element, key);
      if (!cmp) {
        return element;
      } else if (cmp < 0) {
        l = mid + 1;
      } else if (mid > 0) {
        r = mid - 1;
      } else {
        break;
      }
    }
  }
  return NULL;
}

// assert vec != NULL && comparator != NULL
void *vector_find(struct vector *vec, const void *key,
                  int (*comparator)(const void *, const void *)) {
  for (size_t i = 0; i < vector_size(vec); i++) {
    void *element = vector_get(vec, i);
    if (!comparator(element, key)) return element;
  }
  return NULL;
}
