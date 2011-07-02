#!/bin/bash

if [ ! -e ddd-3.3.12.tar.gz ]; then
    wget http://ftp.gnu.org/gnu/ddd/ddd-3.3.12.tar.gz
fi
rm -rf ddd-3.3.12
tar zxf ddd-3.3.12.tar.gz
cd ddd-3.3.12
patch ddd/strclass.C <<EOF
--- ddd-3.3.12-new/ddd/strclass.C	2011-06-25 19:58:01.344386001 +0100
+++ ddd-3.3.12-old/ddd/strclass.C	2009-02-11 17:25:06.000000000 +0000
@@ -41,2 +41,3 @@
 #include <stdlib.h>
+#include <stdio.h>
 
EOF
patch ddd/GDBAgent.C <<EOF
--- ddd-3.3.12-new/ddd/GDBAgent.C	2011-06-25 20:03:55.464386002 +0100
+++ ddd-3.3.12-old/ddd/GDBAgent.C	2009-02-11 17:25:06.000000000 +0000
@@ -3202,3 +3202,3 @@
 	normalize_address(end_);
+	cmd += ',';
-	cmd += ' ';
 	cmd += end_;
EOF
./configure
make
sudo make install
rm -rf ddd-3.3.12
