rm -rf xml man
doxygen
../../doxy2man/doxy2man -o man -s 3 --short-pkg Kronosnet --pkg "Kronosnet Programmer's Manual" xml/libknet_8h.xml
