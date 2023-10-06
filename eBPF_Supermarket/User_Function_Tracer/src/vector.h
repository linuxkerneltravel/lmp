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
// A dynamic array similar to std::vector, but has limit capabitily

#ifndef UTRACE_VECTOR_H
#define UTRACE_VECTOR_H

#include <stdbool.h>
#include <stddef.h>

typedef void (*vector_element_free_t)(void *element);

/**
 * @brief a dynamic array
 */
struct vector {
  size_t size;                /**< stored number of element */
  size_t capacity;            /**< allocated number of element */
  size_t element_size;        /**< size of one element */
  void *data;                 /**< element array */
  vector_element_free_t free; /**< element destructor */
};

/**
 * @brief creates a empty vector that stores element with size element_size
 * @param[in] element_size size of one element to be stored
 */
struct vector *vector_init(size_t element_size, vector_element_free_t free);

/**
 * @brief free the vector
 * @param[in] vec
 */
void vector_free(struct vector *vec);

/**
 * @brief get the size of the input vector
 * @param[in] vec
 */
size_t vector_size(const struct vector *vec);

/**
 * @brief check if the input vector is empty, i.e., size is 0
 * @param[in] vec
 */
bool vector_empty(const struct vector *vec);

/**
 * @brief get the index th element of the input vecotr
 * @param[in] vec
 * @param[in] index array index
 */
void *vector_get(struct vector *vec, size_t index);

/**
 * @brief get the const version of the index th element of the input vecotr
 * @param[in] vec
 * @param[in] index array index
 */
const void *vector_const_get(const struct vector *vec, size_t index);

/**
 * @brief get the first element of the input vecotr
 * @param[in] vec
 */
void *vector_front(struct vector *vec);

/**
 * @brief get the last element of the input vecotr
 * @param[in] vec
 */
void *vector_back(struct vector *vec);

/**
 * @brief allocate at least size * element_size memory
 * @param[in] vec
 * @param[in] size
 */
int vector_reserve(struct vector *vec, size_t size);

/**
 * @brief insert one element to the vector at the end
 * @param[in] vec
 * @param[in] element
 */
int vector_push_back(struct vector *vector, const void *element);

/**
 * @brief pop the end element in the vector
 * @param[in] vec
 * @param[in] element
 */
void vector_pop_back(struct vector *vector);

/**
 * @brief clear the vector
 * @param[in] vec
 */
void vector_clear(struct vector *vector);

/**
 * @brief sort the vector
 * @param[in] vec
 * @param[in] comparator
 */
void vector_sort(struct vector *vec, int (*comparator)(const void *, const void *));

/**
 * @brief unique the vector
 * @param[in] vec
 * @param[in] comparator
 */
void vector_unique(struct vector *vec, int (*comparator)(const void *, const void *));

/**
 * @brief search key in the vector using binary search
 * @param[in] vec sorted
 * @param[in] key
 * @param[in] comparator
 */
void *vector_binary_search(struct vector *vec, const void *key,
                           int (*comparator)(const void *, const void *));

/**
 * @brief search key in the vector
 * @param[in] vec
 * @param[in] key
 * @param[in] comparator
 */
void *vector_find(struct vector *vec, const void *key,
                  int (*comparator)(const void *, const void *));

#endif  // UTRACE_VECTOR_H