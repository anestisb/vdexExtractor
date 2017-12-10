# Vdex Extractor

Command line tool to decompile and extract Android Dex bytecode from Vdex files that are generated
along with Oat files when optimizing bytecode from dex2oat ART runtime compiler. Vdex file format
has been introduced in the Oreo (API-26) build. More information is available [here][vdex-cr]. It
should be noted that Oat files are no longer storing the matching Dex files inside their `.rodata`
section. Instead they're always paired with a matching Vdex file.


## Compile

* Clone this repository
* Install Android NDK if you want to cross-compile for Android devices
* Invoke `make.sh` bash script with desired build target
  * `$ ./make.sh` - if CC not defined from env use gcc by default
  * `$ ./make.sh gcc` - compile with gcc
  * `$ ./make.sh clang` - compile with clang
  * `$ ./make.sh cross-android` - cross-compile (armeabi-v7a, arm64-v8a, x86 &
  x86_64) for Android with NDK
* Executables are copied under the `bin` directory
* For debug builds use `$ DEBUG=true ./make.sh`


## Usage

```
$ bin/vdexExtractor -h
              vdexExtractor ver. 0.4.0
    Anestis Bechtsoudis <anestis@census-labs.com>
  Copyright 2017 by CENSUS S.A. All Rights Reserved.

 -i, --input=<path>   : input dir (1 max depth) or single file
 -o, --output=<path>  : output path (default is same as input)
 -f, --file-override  : allow output file override if already exists (default: false)
 --no-unquicken       : disable unquicken bytecode decompiler (don't de-odex)
 --deps               : dump verified dependencies information
 --dis                : enable bytecode disassembler
 --new-crc=<path>     : text file with extracted Apk or Dex file location checksum(s)
 -v, --debug=LEVEL    : log level (0 - FATAL ... 4 - DEBUG), default: '3' (INFO)
 -l, --log-file=<path>: save disassembler and/or verified dependencies output to log file (default is STDOUT)
 -h, --help           : this help
```


## Bytecode Unquickening Decompiler

The Vdex file includes all quick_info data (old vtable) required to revert the dex-to-dex
transformations applied during bytecode optimization. The idea here is to create a quick standalone
tool capable to revert optimized bytecode, that does not require building the entire libart from
AOSP.

The Vdex fully unquicken functionality has been also implemented as part of the AOSP oatdump libart
tool. The upstream contribution is available [here][aosp-master]. If you want to use oatdump with
Oreo release you can use the corresponding patch [here][oatdump-oreo] or fork and build (inside and
AOSP_SRC_ROOT workspace) the oreo-release branch of the [oatdump++][oatdump-plus] tool.


## Verified Dependencies Iterator

When the Dex bytecode files are compiled (optimized) for the first time, dex2oat executes the
verification dependencies collector as part of the MethodVerifier The verification dependencies
collector class is used to record resolution outcomes and type assignability tests of
classes/methods/fields defined in the classpath. The compilation driver initializes the class and
registers all Dex files which are being compiled. Classes defined in Dex files outside of this set
(or synthesized classes without associated Dex files) are considered being in the classpath. All
recorded dependencies are stored in the generated Vdex file along with the corresponding Oat file
from the OatWriter class.

vdexExtractor tool integrates a Vdex dependencies walker function that is capable to iterate all
dependencies information and dump them in a human readable format. The following snippet
demonstrates a dependencies dump example of a sample Vdex file.

```
$ bin/vdexExtractor -i /tmp/BasicDreams.vdex -o /tmp --deps -f
[INFO] Processing 1 file(s) from /tmp/BasicDreams.vdex
------- Vdex Deps Info -------
dex file #0
 extra strings: number_of_strings=2
  0000: 'Ljava/lang/Thread;'
  0001: 'Ljava/lang/Throwable;'
 assignable type sets: number_of_sets=8
  0000: 'Landroid/service/dreams/DreamService;' must be assignable to 'Landroid/content/Context;'
  0001: 'Landroid/view/TextureView;' must be assignable to 'Landroid/view/View;'
  0002: 'Ljava/nio/FloatBuffer;' must be assignable to 'Ljava/nio/Buffer;'
  0003: 'Ljava/nio/ShortBuffer;' must be assignable to 'Ljava/nio/Buffer;'
  0004: 'Landroid/os/HandlerThread;' must be assignable to 'Ljava/lang/Thread;'
  0005: 'Ljava/lang/IllegalArgumentException;' must be assignable to 'Ljava/lang/Throwable;'
  0006: 'Ljava/lang/InterruptedException;' must be assignable to 'Ljava/lang/Throwable;'
  0007: 'Ljava/lang/RuntimeException;' must be assignable to 'Ljava/lang/Throwable;'
 unassignable type sets: number_of_sets=0
 class dependencies: number_of_classes=34
  0000: 'Landroid/graphics/Color;' 'must' be resolved with access flags '1'
  0001: 'Landroid/graphics/SurfaceTexture;' 'must' be resolved with access flags '1'
  0002: 'Landroid/opengl/GLES20;' 'must' be resolved with access flags '1'
  0003: 'Landroid/opengl/GLUtils;' 'must' be resolved with access flags '1'
  0004: 'Landroid/os/Handler;' 'must' be resolved with access flags '1'
  0005: 'Landroid/os/HandlerThread;' 'must' be resolved with access flags '1'
  0006: 'Landroid/os/SystemClock;' 'must' be resolved with access flags '1'
  0007: 'Landroid/service/dreams/DreamService;' 'must' be resolved with access flags '1'
  0008: 'Landroid/util/Log;' 'must' be resolved with access flags '1'
  0009: 'Landroid/view/Choreographer;' 'must' be resolved with access flags '1'
  0010: 'Landroid/view/TextureView;' 'must' be resolved with access flags '1'
  0011: 'Ljava/lang/Class;' 'must' be resolved with access flags '1'
  0012: 'Ljava/lang/IllegalArgumentException;' 'must' be resolved with access flags '1'
  0013: 'Ljava/lang/Integer;' 'must' be resolved with access flags '1'
  0014: 'Ljava/lang/InterruptedException;' 'must' be resolved with access flags '1'
  0015: 'Ljava/lang/Math;' 'must' be resolved with access flags '1'
  0016: 'Ljava/lang/Object;' 'must' be resolved with access flags '1'
  0017: 'Ljava/lang/RuntimeException;' 'must' be resolved with access flags '1'
  0018: 'Ljava/lang/String;' 'must' be resolved with access flags '1'
  0019: 'Ljava/lang/StringBuilder;' 'must' be resolved with access flags '1'
  0020: 'Ljava/nio/ByteBuffer;' 'must' be resolved with access flags '1'
  0021: 'Ljava/nio/ByteOrder;' 'must' be resolved with access flags '1'
  0022: 'Ljava/nio/FloatBuffer;' 'must' be resolved with access flags '1'
  0023: 'Ljava/nio/ShortBuffer;' 'must' be resolved with access flags '1'
  0024: 'Ljavax/microedition/khronos/egl/EGL10;' 'must' be resolved with access flags '513'
  0025: 'Ljavax/microedition/khronos/egl/EGLConfig;' 'must' be resolved with access flags '1'
  0026: 'Ljavax/microedition/khronos/egl/EGLContext;' 'must' be resolved with access flags '1'
  0027: 'Ljavax/microedition/khronos/egl/EGLDisplay;' 'must' be resolved with access flags '1'
  0028: 'Ljavax/microedition/khronos/egl/EGLSurface;' 'must' be resolved with access flags '1'
  0029: '[F' 'must' be resolved with access flags '1'
  0030: '[I' 'must' be resolved with access flags '1'
  0031: '[Ljava/lang/Object;' 'must' be resolved with access flags '1'
  0032: '[Ljavax/microedition/khronos/egl/EGLConfig;' 'must' be resolved with access flags '1'
  0033: '[S' 'must' be resolved with access flags '1'
 field dependencies: number_of_fields=4
  0000: 'Ljavax/microedition/khronos/egl/EGL10;'->'EGL_DEFAULT_DISPLAY':'Ljava/lang/Object;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;' and have the access flags '9'
  0001: 'Ljavax/microedition/khronos/egl/EGL10;'->'EGL_NO_CONTEXT':'Ljavax/microedition/khronos/egl/EGLContext;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;' and have the access flags '9'
  0002: 'Ljavax/microedition/khronos/egl/EGL10;'->'EGL_NO_DISPLAY':'Ljavax/microedition/khronos/egl/EGLDisplay;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;' and have the access flags '9'
  0003: 'Ljavax/microedition/khronos/egl/EGL10;'->'EGL_NO_SURFACE':'Ljavax/microedition/khronos/egl/EGLSurface;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;' and have the access flags '9'
 method dependencies: number_of_methods=84
  0000: 'Landroid/graphics/Color;'->'HSVToColor':'([F)I' is expected to be in class 'Landroid/graphics/Color;', have the access flags '9
  0001: 'Landroid/opengl/GLES20;'->'glAttachShader':'(II)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0002: 'Landroid/opengl/GLES20;'->'glClear':'(I)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0003: 'Landroid/opengl/GLES20;'->'glClearColor':'(FFFF)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0004: 'Landroid/opengl/GLES20;'->'glCompileShader':'(I)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0005: 'Landroid/opengl/GLES20;'->'glCreateProgram':'()I' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0006: 'Landroid/opengl/GLES20;'->'glCreateShader':'(I)I' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0007: 'Landroid/opengl/GLES20;'->'glDeleteProgram':'(I)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0008: 'Landroid/opengl/GLES20;'->'glDeleteShader':'(I)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0009: 'Landroid/opengl/GLES20;'->'glDrawArrays':'(III)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0010: 'Landroid/opengl/GLES20;'->'glEnableVertexAttribArray':'(I)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0011: 'Landroid/opengl/GLES20;'->'glGetAttribLocation':'(ILjava/lang/String;)I' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0012: 'Landroid/opengl/GLES20;'->'glGetError':'()I' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0013: 'Landroid/opengl/GLES20;'->'glGetProgramInfoLog':'(I)Ljava/lang/String;' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0014: 'Landroid/opengl/GLES20;'->'glGetProgramiv':'(II[II)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0015: 'Landroid/opengl/GLES20;'->'glGetShaderInfoLog':'(I)Ljava/lang/String;' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0016: 'Landroid/opengl/GLES20;'->'glGetShaderiv':'(II[II)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0017: 'Landroid/opengl/GLES20;'->'glLinkProgram':'(I)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0018: 'Landroid/opengl/GLES20;'->'glShaderSource':'(ILjava/lang/String;)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0019: 'Landroid/opengl/GLES20;'->'glUseProgram':'(I)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0020: 'Landroid/opengl/GLES20;'->'glVertexAttribPointer':'(IIIZILjava/nio/Buffer;)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0021: 'Landroid/opengl/GLES20;'->'glViewport':'(IIII)V' is expected to be in class 'Landroid/opengl/GLES20;', have the access flags '9
  0022: 'Landroid/opengl/GLUtils;'->'getEGLErrorString':'(I)Ljava/lang/String;' is expected to be in class 'Landroid/opengl/GLUtils;', have the access flags '9
  0023: 'Landroid/os/Handler;'->'<init>':'(Landroid/os/Looper;)V' is expected to be in class 'Landroid/os/Handler;', have the access flags '1
  0024: 'Landroid/os/Handler;'->'post':'(Ljava/lang/Runnable;)Z' is expected to be in class 'Landroid/os/Handler;', have the access flags '1
  0025: 'Landroid/os/HandlerThread;'->'<init>':'(Ljava/lang/String;)V' is expected to be in class 'Landroid/os/HandlerThread;', have the access flags '1
  0026: 'Landroid/os/HandlerThread;'->'getLooper':'()Landroid/os/Looper;' is expected to be in class 'Landroid/os/HandlerThread;', have the access flags '1
  0027: 'Landroid/os/HandlerThread;'->'join':'()V' is expected to be in class 'Ljava/lang/Thread;', have the access flags '1
  0028: 'Landroid/os/HandlerThread;'->'quit':'()Z' is expected to be in class 'Landroid/os/HandlerThread;', have the access flags '1
  0029: 'Landroid/os/HandlerThread;'->'start':'()V' is expected to be in class 'Ljava/lang/Thread;', have the access flags '1
  0030: 'Landroid/os/SystemClock;'->'uptimeMillis':'()J' is expected to be in class 'Landroid/os/SystemClock;', have the access flags '9
  0031: 'Landroid/service/dreams/DreamService;'->'<init>':'()V' is expected to be in class 'Landroid/service/dreams/DreamService;', have the access flags '1
  0032: 'Landroid/service/dreams/DreamService;'->'onAttachedToWindow':'()V' is expected to be in class 'Landroid/service/dreams/DreamService;', have the access flags '1
  0033: 'Landroid/service/dreams/DreamService;'->'onCreate':'()V' is expected to be in class 'Landroid/service/dreams/DreamService;', have the access flags '1
  0034: 'Landroid/util/Log;'->'d':'(Ljava/lang/String;Ljava/lang/String;)I' is expected to be in class 'Landroid/util/Log;', have the access flags '9
  0035: 'Landroid/util/Log;'->'e':'(Ljava/lang/String;Ljava/lang/String;)I' is expected to be in class 'Landroid/util/Log;', have the access flags '9
  0036: 'Landroid/util/Log;'->'w':'(Ljava/lang/String;Ljava/lang/String;)I' is expected to be in class 'Landroid/util/Log;', have the access flags '9
  0037: 'Landroid/view/Choreographer;'->'getInstance':'()Landroid/view/Choreographer;' is expected to be in class 'Landroid/view/Choreographer;', have the access flags '9
  0038: 'Landroid/view/Choreographer;'->'postFrameCallback':'(Landroid/view/Choreographer$FrameCallback;)V' is expected to be in class 'Landroid/view/Choreographer;', have the access flags '1
  0039: 'Landroid/view/Choreographer;'->'removeFrameCallback':'(Landroid/view/Choreographer$FrameCallback;)V' is expected to be in class 'Landroid/view/Choreographer;', have the access flags '1
  0040: 'Landroid/view/TextureView;'->'<init>':'(Landroid/content/Context;)V' is expected to be in class 'Landroid/view/TextureView;', have the access flags '1
  0041: 'Landroid/view/TextureView;'->'setSurfaceTextureListener':'(Landroid/view/TextureView$SurfaceTextureListener;)V' is expected to be in class 'Landroid/view/TextureView;', have the access flags '1
  0042: 'Lcom/android/dreams/basic/Colors;'->'setContentView':'(Landroid/view/View;)V' is expected to be in class 'Landroid/service/dreams/DreamService;', have the access flags '1
  0043: 'Lcom/android/dreams/basic/Colors;'->'setFullscreen':'(Z)V' is expected to be in class 'Landroid/service/dreams/DreamService;', have the access flags '1
  0044: 'Lcom/android/dreams/basic/Colors;'->'setInteractive':'(Z)V' is expected to be in class 'Landroid/service/dreams/DreamService;', have the access flags '1
  0045: 'Lcom/android/dreams/basic/Colors;'->'setLowProfile':'(Z)V' is expected to be in class 'Landroid/service/dreams/DreamService;', have the access flags '1
  0046: 'Ljava/lang/Class;'->'getSimpleName':'()Ljava/lang/String;' is expected to be in class 'Ljava/lang/Class;', have the access flags '1
  0047: 'Ljava/lang/IllegalArgumentException;'->'<init>':'(Ljava/lang/String;)V' is expected to be in class 'Ljava/lang/IllegalArgumentException;', have the access flags '1
  0048: 'Ljava/lang/Integer;'->'toHexString':'(I)Ljava/lang/String;' is expected to be in class 'Ljava/lang/Integer;', have the access flags '9
  0049: 'Ljava/lang/Integer;'->'valueOf':'(I)Ljava/lang/Integer;' is expected to be in class 'Ljava/lang/Integer;', have the access flags '9
  0050: 'Ljava/lang/Math;'->'random':'()D' is expected to be in class 'Ljava/lang/Math;', have the access flags '9
  0051: 'Ljava/lang/Math;'->'sin':'(D)D' is expected to be in class 'Ljava/lang/Math;', have the access flags '9
  0052: 'Ljava/lang/Object;'->'<init>':'()V' is expected to be in class 'Ljava/lang/Object;', have the access flags '1
  0053: 'Ljava/lang/RuntimeException;'->'<init>':'(Ljava/lang/String;)V' is expected to be in class 'Ljava/lang/RuntimeException;', have the access flags '1
  0054: 'Ljava/lang/StringBuilder;'->'<init>':'()V' is expected to be in class 'Ljava/lang/StringBuilder;', have the access flags '1
  0055: 'Ljava/lang/StringBuilder;'->'append':'(I)Ljava/lang/StringBuilder;' is expected to be in class 'Ljava/lang/StringBuilder;', have the access flags '1
  0056: 'Ljava/lang/StringBuilder;'->'append':'(Ljava/lang/String;)Ljava/lang/StringBuilder;' is expected to be in class 'Ljava/lang/StringBuilder;', have the access flags '1
  0057: 'Ljava/lang/StringBuilder;'->'toString':'()Ljava/lang/String;' is expected to be in class 'Ljava/lang/StringBuilder;', have the access flags '1
  0058: 'Ljava/nio/ByteBuffer;'->'allocateDirect':'(I)Ljava/nio/ByteBuffer;' is expected to be in class 'Ljava/nio/ByteBuffer;', have the access flags '9
  0059: 'Ljava/nio/ByteBuffer;'->'asFloatBuffer':'()Ljava/nio/FloatBuffer;' is expected to be in class 'Ljava/nio/ByteBuffer;', have the access flags '1
  0060: 'Ljava/nio/ByteBuffer;'->'asShortBuffer':'()Ljava/nio/ShortBuffer;' is expected to be in class 'Ljava/nio/ByteBuffer;', have the access flags '1
  0061: 'Ljava/nio/ByteBuffer;'->'order':'(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;' is expected to be in class 'Ljava/nio/ByteBuffer;', have the access flags '1
  0062: 'Ljava/nio/ByteOrder;'->'nativeOrder':'()Ljava/nio/ByteOrder;' is expected to be in class 'Ljava/nio/ByteOrder;', have the access flags '9
  0063: 'Ljava/nio/FloatBuffer;'->'clear':'()Ljava/nio/Buffer;' is expected to be in class 'Ljava/nio/Buffer;', have the access flags '1
  0064: 'Ljava/nio/FloatBuffer;'->'position':'(I)Ljava/nio/Buffer;' is expected to be in class 'Ljava/nio/Buffer;', have the access flags '1
  0065: 'Ljava/nio/FloatBuffer;'->'put':'(F)Ljava/nio/FloatBuffer;' is expected to be in class 'Ljava/nio/FloatBuffer;', have the access flags '1
  0066: 'Ljava/nio/FloatBuffer;'->'put':'([F)Ljava/nio/FloatBuffer;' is expected to be in class 'Ljava/nio/FloatBuffer;', have the access flags '1
  0067: 'Ljava/nio/ShortBuffer;'->'position':'(I)Ljava/nio/Buffer;' is expected to be in class 'Ljava/nio/Buffer;', have the access flags '1
  0068: 'Ljava/nio/ShortBuffer;'->'put':'([S)Ljava/nio/ShortBuffer;' is expected to be in class 'Ljava/nio/ShortBuffer;', have the access flags '1
  0069: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglChooseConfig':'(Ljavax/microedition/khronos/egl/EGLDisplay;[I[Ljavax/microedition/khronos/egl/EGLConfig;I[I)Z' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0070: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglCreateContext':'(Ljavax/microedition/khronos/egl/EGLDisplay;Ljavax/microedition/khronos/egl/EGLConfig;Ljavax/microedition/khronos/egl/EGLContext;[I)Ljavax/microedition/khronos/egl/EGLContext;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0071: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglCreateWindowSurface':'(Ljavax/microedition/khronos/egl/EGLDisplay;Ljavax/microedition/khronos/egl/EGLConfig;Ljava/lang/Object;[I)Ljavax/microedition/khronos/egl/EGLSurface;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0072: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglDestroyContext':'(Ljavax/microedition/khronos/egl/EGLDisplay;Ljavax/microedition/khronos/egl/EGLContext;)Z' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0073: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglDestroySurface':'(Ljavax/microedition/khronos/egl/EGLDisplay;Ljavax/microedition/khronos/egl/EGLSurface;)Z' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0074: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglGetCurrentContext':'()Ljavax/microedition/khronos/egl/EGLContext;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0075: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglGetCurrentSurface':'(I)Ljavax/microedition/khronos/egl/EGLSurface;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0076: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglGetDisplay':'(Ljava/lang/Object;)Ljavax/microedition/khronos/egl/EGLDisplay;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0077: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglGetError':'()I' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0078: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglInitialize':'(Ljavax/microedition/khronos/egl/EGLDisplay;[I)Z' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0079: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglMakeCurrent':'(Ljavax/microedition/khronos/egl/EGLDisplay;Ljavax/microedition/khronos/egl/EGLSurface;Ljavax/microedition/khronos/egl/EGLSurface;Ljavax/microedition/khronos/egl/EGLContext;)Z' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0080: 'Ljavax/microedition/khronos/egl/EGL10;'->'eglSwapBuffers':'(Ljavax/microedition/khronos/egl/EGLDisplay;Ljavax/microedition/khronos/egl/EGLSurface;)Z' is expected to be in class 'Ljavax/microedition/khronos/egl/EGL10;', have the access flags '1
  0081: 'Ljavax/microedition/khronos/egl/EGLContext;'->'equals':'(Ljava/lang/Object;)Z' is expected to be in class 'Ljava/lang/Object;', have the access flags '1
  0082: 'Ljavax/microedition/khronos/egl/EGLContext;'->'getEGL':'()Ljavax/microedition/khronos/egl/EGL;' is expected to be in class 'Ljavax/microedition/khronos/egl/EGLContext;', have the access flags '9
  0083: 'Ljavax/microedition/khronos/egl/EGLSurface;'->'equals':'(Ljava/lang/Object;)Z' is expected to be in class 'Ljava/lang/Object;', have the access flags '1
 unverified classes: number_of_classes=0
----- EOF Vdex Deps Info -----
[INFO] 1 out of 1 Vdex files have been processed
[INFO] 1 Dex files have been extracted in total
[INFO] Extracted Dex files are available in '/tmp'
```


## Integrated Disassembler

To debug the decompiler and assist the Dex bytecode investigation tasks, a light disassembler has
been implemented. The disassembler output is very similar to the one provided by the AOSP dexdump2
utility of the `platform/art` project. The disassembler can be used independently of the
unquickening decompiler.

A sample output is illustrated in the following snippet. Lines prefixed with `[new]` illustrate the
output of the decompiled instruction (previous line) located in that offset. Notice that all the
quickened offsets and vtable references have been reverted back to original signatures and
prototypes.

```
$ bin/vdexExtractor -i /tmp/Videos.vdex -o /tmp -f --dis -l /tmp/dis.log
[INFO] Processing 1 file(s) from /tmp/Videos.vdex
[INFO] 1 out of 1 Vdex files have been processed
[INFO] 2 Dex files have been extracted in total
[INFO] Extracted Dex files are available in '/tmp'
$ head -90 /tmp/dis.log
------ Dex Header Info ------
magic        : dex-035
checksum     : e14de163 (3779977571)
signature    : 9a91f8e5f2afe2c6b5c2b4853832d3c5ed01aef8
fileSize     : 8ca638 (9217592)
headerSize   : 70 (112)
endianTag    : 12345678 (305419896)
linkSize     : 0 (0)
linkOff      : 0 (0)
mapOff       : 8ca568 (9217384)
stringIdsSize: ef06 (61190)
stringIdsOff : 70 (112)
typeIdsSize  : 29f4 (10740)
typeIdsOff   : 3bc88 (244872)
protoIdsSize : 3df9 (15865)
protoIdsOff  : 46458 (287832)
fieldIdsSize : a79d (42909)
fieldIdsOff  : 74c04 (478212)
methodIdsSize: fed7 (65239)
methodIdsOff : c88ec (821484)
classDefsSize: 2288 (8840)
classDefsOff : 147fa4 (1343396)
dataSize     : 73d594 (7591316)
dataOff      : 18d0a4 (1626276)
-----------------------------
file #0: classDefsSize=8840
  class #0: a.a ('La$a;')
   access=0601 (PUBLIC INTERFACE ABSTRACT)
   source_file=SourceFile, class_data_off=851907 (8722695)
   static_fields=0, instance_fields=0, direct_methods=0, virtual_methods=2
   virtual_method #0: onMenuItemSelected (La;Landroid/view/MenuItem;)Z
    access=0401 (PUBLIC ABSTRACT)
    codeOff=0 (0)
   virtual_method #1: invokeItem (Landroid/support/v7/view/menu/MenuItemImpl;)Z
    access=0401 (PUBLIC ABSTRACT)
    codeOff=0 (0)
  class #1: a.b ('La$b;')
   access=0601 (PUBLIC INTERFACE ABSTRACT)
   source_file=SourceFile, class_data_off=851913 (8722707)
   static_fields=0, instance_fields=0, direct_methods=0, virtual_methods=1
   virtual_method #0: invokeItem (Landroid/support/v7/view/menu/MenuItemImpl;)Z
    access=0401 (PUBLIC ABSTRACT)
    codeOff=0 (0)
  class #2: SupportMenu ('Landroid/support/v4/internal/view/SupportMenu;')
   access=0601 (PUBLIC INTERFACE ABSTRACT)
   source_file=SourceFile, class_data_off=0 (0)
  class #3: a ('La;')
   access=0001 (PUBLIC)
   source_file=SourceFile, class_data_off=85191b (8722715)
   static_fields=1, instance_fields=25, direct_methods=12, virtual_methods=74
   direct_method #0: <clinit> ()V
    access=10008 (STATIC CONSTRUCTOR)
    codeOff=1abb50 (1751888)
    quickening_size=4 (4)
      1abb60: 1260                                   |0000: const/4 v0, #int 6 // #6
      1abb62: 2300 e426                              |0001: new-array v0, v0, [I // type@26e4
      1abb66: 2600 0700 0000                         |0003: fill-array-data v0, 0000000a // +00000000
      1abb6c: 6900 1900                              |0006: sput-object v0, La;.sCategoryToOrder:[I // field@0019
      1abb70: 7300                                   |0008: return-void-no-barrier
[new] 1abb70: 0e00                                   |0008: return-void
      1abb72: 0000                                   |0009: nop // spacer
      1abb74: 0003 0400 0600 0000 0100 0000 0400 ... |000a: array-data (16 units)
   direct_method #1: invokeItem (Landroid/support/v7/view/menu/MenuItemImpl;)Z
    access=10001 (PUBLIC CONSTRUCTOR)
    codeOff=1abb94 (1751956)
    quickening_size=22 (34)
      1abba4: 1211                                   |0000: const/4 v1, #int 1 // #1
      1abba6: 1200                                   |0001: const/4 v0, #int 0 // #0
      1abba8: 7010 dbf9 0200                         |0002: invoke-direct {v2}, Ljava/lang/Object;.<init>:()V // method@f9db
      1abbae: e620 4000                              |0005: iput-quick v0, v2, [obj+0040]
[new] 1abbae: 5920 0400                              |0005: iput v0, v2, La;.mDefaultShowAsAction:I // field@0004
      1abbb2: eb20 4a00                              |0007: iput-boolean-quick v0, v2, [obj+004a]
[new] 1abbb2: 5c20 1200                              |0007: iput-boolean v0, v2, La;.mPreventDispatchingItemsChanged:Z // field@0012
      1abbb6: eb20 4700                              |0009: iput-boolean-quick v0, v2, [obj+0047]
[new] 1abbb6: 5c20 0d00                              |0009: iput-boolean v0, v2, La;.mItemsChangedWhileDispatchPrevented:Z // field@000d
      1abbba: eb20 4d00                              |000b: iput-boolean-quick v0, v2, [obj+004d]
[new] 1abbba: 5c20 1600                              |000b: iput-boolean v0, v2, La;.mStructureChangedWhileDispatchPrevented:Z // field@0016
      1abbbe: eb20 4800                              |000d: iput-boolean-quick v0, v2, [obj+0048]
[new] 1abbbe: 5c20 0f00                              |000d: iput-boolean v0, v2, La;.mOptionalIconsVisible:Z // field@000f
      1abbc2: eb20 4500                              |000f: iput-boolean-quick v0, v2, [obj+0045]
[new] 1abbc2: 5c20 0a00                              |000f: iput-boolean v0, v2, La;.mIsClosing:Z // field@000a
      1abbc6: 2200 fe25                              |0011: new-instance v0, Ljava/util/ArrayList; // type@25fe
      1abbca: 7010 6bfb 0000                         |0013: invoke-direct {v0}, Ljava/util/ArrayList;.<init>:()V // method@fb6b
      1abbd0: e820 3800                              |0016: iput-object-quick v0, v2, [obj+0038]
[new] 1abbd0: 5b20 1700                              |0016: iput-object v0, v2, La;.mTempShortcutItemList:Ljava/util/ArrayList; // field@0017
      1abbd4: 2200 2c26                              |0018: new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList; // type@262c
      1abbd8: 7010 cdfc 0000                         |001a: invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;.<init>:()V // method@fccd
      1abbde: e820 3000                              |001d: iput-object-quick v0, v2, [obj+0030]
[new] 1abbde: 5b20 1100                              |001d: iput-object v0, v2, La;.mPresenters:Ljava/util/concurrent/CopyOnWriteArrayList; // field@0011
      1abbe2: e823 1000                              |001f: iput-object-quick v3, v2, [obj+0010]
```


## Utility Scripts

* **scripts/extract-apps-from-device.sh**

  Extract ART compiler output resources (oat, art, vdex) of installed packages (user and system)
  from a connected Android device. Also supports extracting APK archives of installed packages. Some
  system app data might fail to extract without root access due to applied DAC permissions.

  ```text
  $ scripts/extract-apps-from-device.sh -h
    Usage: extract-apps-from-device.sh [options]
      options:
        -o|--output <dir>  : Output directory to save extracted data (default is '.')
        -d|--device <devID>: Device serial to use instead of default interactive selection
        --system-apps      : Extract system apps too (default is user apps only)
        --apks             : Extract apks (default is optimized files only)
        -h|--help          : This help message
  $ scripts/extract-apps-from-device.sh --system-apps -o /tmp/art_data --apks
  [INFO]: Enumerating connected Android devices
  [INFO]: Trying to extract data from '163' packages
  [INFO]: Extracted data stored under '/tmp/art_data'
  ```

* **scripts/update-vdex-location-checksums.sh**

  Update Vdex file location checksums with CRCs extracted from input Apk archive file. More
  information on how this feature was used to trick the ART runtime book keeping mechanism and
  bypass SafetyNet application integrity checks is available [here][census-snet].

  ```text
  $ scripts/update-vdex-location-checksums.sh -h
    Usage: update-vdex-location-checksums.sh [options]
      options:
        -i|--input <file> : Input Vdex file to repair location checksum(s) within
        -a|--app <file>   : Input Apk file to extract location checksum(s) from
        -o|--output <dir> : Directory to save updated Vdex file (default is '.')
        -h|--help         : This help message
  ```


## Changelog

* __0.4.0__ - xx December 2017
  * Add Vdex 010 (API-27) support by defining different parser & decompiler backend engines that are
    version specific
  * Fix a bug in verified dependencies iterator that presented results out of order
* __0.3.1__ - 17 November 2017
  * Add option to update checksum location of Vdex file (`-n, --new-crc`). Feature mostly targets
    use-cases were a backwards compatibility fix of the Vdex file is required without having to
    dex2oat recompile.
  * Implement class name recover information gather feature (`-r, --class-recover`)
  * Add timer utility functions to measure time spend to unquicken each input Vdex file
  * Use external log file only for disassembler & verified dependencies information output
  * Disassembler output performance improvements
  * Improve performance when decompiling and disassembling at the same run
  * Logging facility improvements
  * Improve code quality by removing duplicate code
* __0.3.0__ - 28 October 2017
  * Implement Vdex verified dependencies information iterator (`-D, --dump-deps`)
  * Enable Dex disassembler without requiring to unquicken bytecode
  * Improve Dex disassembler output by resolving class & method definitions
  * Improve Dex disassembler output by annotating classes & methods access flags
  * Fixed a bug when printing number of class fields and method from Dex disassembler
  * Utility script to automate extraction of ART compiler output resources from a device
  * Dex file API improvements
* __0.2.3__ - 16 October 2017
  * Improve disassembler output when decompiling NOP instructions (effectively ignore spacers)
* __0.2.2__ - 16 October 2017
  * Fix UAF bug when processing multiple files
* __0.2.1__ - 16 October 2017
  * Option to save output to log file instead of (default) STDOUT (`-l, --log-file`)
  * Dump Vdex header information with verbose debug option
  * Fix minor memory leaks & memory corruptions in disassembler engine
* __0.2.0__ - 16 October 2017
  * Unquicken decompiler stable release (`-u, --unquicken`)
  * Implement Dex bytecode disassembler (`-d, --disassemble`)
* __0.1.1__ - 13 October 2017
  * Unquicken decompiler beta release (`-u, --unquicken`)
  * Allow override of output Dex files (`-f, --file-override`)
* __0.1.0__ - 8 October 2017
  * Initial release


## ToDo

* Disassembler performance & usability improvements


## License

```
   Anestis Bechtsoudis <anestis@census-labs.com>
   Copyright 2017 by CENSUS S.A. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

[vdex-cr]: https://android-review.googlesource.com/#/c/264514/
[aosp-master]: https://android.googlesource.com/platform/art/+/a1f56a8dddb88f5377a7dd4ec79640103c713d30
[oatdump-oreo]: https://gist.github.com/anestisb/71d6b0496912f801533dec9d264aa409
[oatdump-plus]: https://github.com/anestisb/oatdump_plus/tree/oreo-release
[census-snet]: https://census-labs.com/news/2017/11/17/examining-the-value-of-safetynet-attestation-as-an-application-integrity-security-control/
