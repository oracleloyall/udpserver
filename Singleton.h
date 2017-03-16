/*
 * Singleton.h
 *
 *  Created on: Mar 16, 2017
 *      Author: oracle
 */

#ifndef DESIGN_SINGLETON_H_
#define DESIGN_SINGLETON_H_

#include <stdlib.h>
#include"../config.h"
typedef struct {
    void* (*ctor)(void *_self);
    void* (*dtor)(void *_self);
    void* (*createInstance)(void *self);
    void *instance;
} _CSingleton;

extern const void *CSingleton;

void *GetInstance(void);

#endif /* DESIGN_SINGLETON_H_ */
