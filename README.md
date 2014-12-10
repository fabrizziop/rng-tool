rng-tool
========

CSPRNG image or file generator (Python 3.4)

This lovely program allows you to specify a CSPRNG (either my own SHA-512 based one or just dumb RC4-drop4096) and a file name. Then, you can choose to create an image (1-bit B/W bmp) of the dimensions you choose, or just save any amount of random bytes to a file.

In RC4 you can specify a key size or just input a manual key in hex. I verified my implementation against the IETF RFC 6229 RC4 test vectors. 
