#!/bin/bash

set -ex

origin_name=$1
upper_name=${origin_name^^}
array=(${origin_name//_/ })
name=""
for var in ${array[@]}
do
   name=$name${var^}
done
class_name=$name"StackCollector"


cp include/bpf/TemplateClass.h include/bpf/$class_name.h
sed -i 's/_TEMPLATE_H__/_SA_'$upper_name'_H__/g' include/bpf/$class_name.h
sed -i 's/TemplateClass/'$class_name'/g' include/bpf/$class_name.h
sed -i 's/template/'$origin_name'/g' include/bpf/$class_name.h

cp src/bpf/TemplateClass.cpp src/bpf/$class_name.cpp
sed -i 's/TemplateClass/'$class_name'/g' src/bpf/$class_name.cpp

cp src/bpf/template.bpf.c src/bpf/$origin_name.bpf.c
sed -i 's/TemplateClass/'$class_name'/g' src/bpf/$origin_name.bpf.c

sed -i '/#include "bpf\/OnCPUStackCollector.h"/a#include "bpf\/'$class_name'.h"' main.cpp

sed -i '/auto cli = (MainOption,/iauto '$name'Option = (clipp::option("'$origin_name'").call([]{ StackCollectorList.push_back(new '$class_name'()); }) %"sample the '$origin_name' of calling stacks") & (SubOption);' main.cpp

sed -i '/OnCpuOption,/a'$name'Option,' main.cpp