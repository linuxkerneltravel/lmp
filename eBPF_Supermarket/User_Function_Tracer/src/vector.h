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

#ifndef UTRACE_VECTOR_H
#define UTRACE_VECTOR_H

#include <stdbool.h>
#include <stddef.h>

typedef void (*vector_element_free_t)(void *element);

struct vector {
  size_t size;                /**< number of elements stored */
  size_t capacity;            /**< number of elements allocated */
  size_t element_size;        /**< size of one element */
  void *data;                 /**< array of elements */
  vector_element_free_t free; /**< element destructor */
};

/**
 * @brief create and init an empty vector malloced from heap that stores elements with size
 *        `element_size`
 * @param[in] element_size size of each stored element
 * @param[in] free destructor for each stored element
 */
struct vector *vector_init(size_t element_size, vector_element_free_t free);

/**
 * @brief free the input vector
 */
void vector_free(struct vector *vec);

/**
 * @brief get the size of the input vector
 */
size_t vector_size(const struct vector *vec);

/**
 * @brief check if the input vector is empty, i.e., size is 0
 */
bool vector_empty(const struct vector *vec);

/**
 * @brief get the `index`-th element of the input vector
 */
void *vector_get(struct vector *vec, size_t index);

/**
 * @brief get the const version of the `index`-th element of the input vector
 */
const void *vector_const_get(const struct vector *vec, size_t index);

/**
 * @brief get the first element of the input vector
 */
void *vector_front(struct vector *vec);

/**
 * @brief get the last element of the input vector
 */
void *vector_back(struct vector *vec);

/**
 * @brief ensure the input vector has allocated at least (`size` * `vec->element_size`) memory
 */
int vector_reserve(struct vector *vec, size_t size);

/**
 * @brief resize the input vector to contain `size` elements,
 *        additional elements are **uninitialized**
 */
int vector_resize(struct vector *vec, size_t size);

/**
 * @brief set the `index`-th element of the input vector to `element`
 */
void vector_set(struct vector *vec, size_t index, const void *element);

/**
 * @brief insert one element to the input vector at the end
 */
int vector_push_back(struct vector *vector, const void *element);

/**
 * @brief pop the last element in the input vector
 */
void vector_pop_back(struct vector *vector);

/**
 * @brief clear the input vector
 */
void vector_clear(struct vector *vector);

/**
 * @brief sort the input vector
 * @param[in] comparator a function used to compare two stored elements
 */
void vector_sort(struct vector *vec, int (*comparator)(const void *, const void *));

/**
 * @brief unique the input vector
 * @param[in] comparator a function used to compare two stored elements
 */
void vector_unique(struct vector *vec, int (*comparator)(const void *, const void *));

/**
 * @brief search the element `key` in the input vector via binary search
 * @param[in] key the searched element
 * @param[in] comparator a function used to compare the stored elements with the searched `key`
 * @details the input vector should be sorted by `comparator` first; O(\log n)
 */
void *vector_binary_search(struct vector *vec, const void *key,
                           int (*comparator)(const void *, const void *));

/**
 * @brief search the element `key` in the input vector sequentially
 * @details O(n)
 */
void *vector_find(struct vector *vec, const void *key,
                  int (*comparator)(const void *, const void *));

#endif  // UTRACE_VECTOR_H
