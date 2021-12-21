#!/bin/bash
read -r -d '' license <<-"EOF"
/*    Copyright (c) 2021-2022, Vaino Kauppila
 *    All rights reserved
 *
 *    This file is part of the programme "c-pass" and use in source and
 *    binary forms, with or without modification, are permitted exclusively
 *    under the terms of the ######### license. You should have received
 *    a copy of the license with this file. If not, please or visit:
 *    ###############.com.
 */
EOF

files=$(grep -rL "Copyright (c) 2021-2022, Vaino Kauppila" * | grep "\.h\|\.c")

for f in $files
do
  echo -e "$license" > temp  
  cat $f >> temp
  mv temp $f
done
