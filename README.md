# Garuda Decompiler Engine
 
This is a simple tool to translate machine code into pseudo-code.

This is just a testing version, it certainly works for most common assembly code which contains basic operations such as *mov*, *lea*, arithmetic and logical operations etc. There are a lot of things to improve and implement. This project is designed to decompile parts of functions in memory where there is some encryption going on. For instance, it doesn't take into account operations where the destination is in the stack. There are a lot of instruction callbacks to implement but the ones currently implemented are the common ones to encrypt/decrypt basic data/memory at run-time.

An example:

![ExampleAsm](https://i.gyazo.com/dcd9007db04874873a04ed29ebff57e6.png)

Translates into this


![ExamplePseudo](https://i.gyazo.com/08b979bb238de8805a9c313bc2a00d7c.png)
