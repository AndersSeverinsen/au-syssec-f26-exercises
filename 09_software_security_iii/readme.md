# Exercises: Software Security III -- Finding Bugs

Today we are talking about different classes of bugs and how we can use tools
to find them.



## 1. Classes of Vulnerabilities

During the course, we have seen many different kinds of vulnerabilities in software.
For assignment 3, you will be asked to reproduce an exploit for one software vulnerability.

1. Think about what *classes of bugs* you can think of, e.g., what you have
   encountered in this course or in other context and collect them on a text file.

- Buffer overflows
- Traffic sniffing
- Man in the middle attacks
- SQL injection
- Cross-site scripting (XSS)

2. Think about whether they are security relevant, i.e., could an attacker exploit them?

- Yes

3. Take a look at the [Common Weakness
   Enumeration](https://cwe.mitre.org/index.html) -- a project that lists and
   categorizes security-related problems and their relationships in software
   and hardware.

   Try to find some of the vulnerability classes you though of in CWE.

   You can for example use the following views to navigate CWE:

    - [CWE VIEW: Software Development](https://cwe.mitre.org/data/definitions/699.html)
    - [CWE VIEW: Research Concepts](https://cwe.mitre.org/data/definitions/1000.html)
    - [CWE VIEW: Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/data/definitions/1337.html)

- [CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)

## 2. Using Sanitizers

C is a widely used programming language.  It is, however, easy to make mistakes
that often lead to security problems behavior.  Fortunately, the available
tooling has improved in recent years.

Very helpful are the so-called *sanitizers* available in the GCC and Clang
compilers.  When enabled, these sanitizers instrument the resulting binary
program with additional checks.  At run-time, the inserted checks are able to
detect certain classes of errors and provider information to the developer
where/how the error occurred.  Hence, it is compile programs (or test suites)
with sanitizers to detect bugs that otherwise would not have had directly
observable consequences.

You are given three programs `address.c`, `thread.c`, and `undefined.c` which
contain very questionable code and different kinds of bugs to demonstrate the
powers of the different sanitizers.  Run `make` to compile them.


### 2.1 AddressSanitizer (ASan)

The manual memory management and the absence of automatic bounds checking in C
are major sources of trouble.  The AddressSanitizer, enabled with
`-fsanitize=address`, is able to detect such mistakes.

Consider the program `address.c` which is obviously buggy.
```bash
$ ./address AAAAAAAAAAAAAAA BBBBBBBBBBBBBBB
What's your name?
lennart
============== Moin lennart ==============
Do you like pointers?
YES!
WTF???
free(): invalid pointer
[1]    2385487 abort (core dumped)  ./address AAAAAAAAAAAAAAA BBBBBBBBBBBBBBB
```
Run it with ASan and see what kind of errors it detects.
```bash
$ ./address_asan AAAAAAAAAAAAAAA BBBBBBBBBBBBBBB
What's your name?
lennart
=================================================================
==10999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000d4 at pc 0x000105276a20 bp 0x00016b45eb30 sp 0x00016b45e2e0
WRITE of size 5 at 0x6020000000d4 thread T0
    #0 0x000105276a1c in strcpy+0x458 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3aa1c)
    #1 0x0001049a0a78 in hello address.c:21
    #2 0x0001049a117c in main address.c:69
    #3 0x00018bd93da0 in start+0x1b4c (dyld:arm64e+0x1fda0)

0x6020000000d4 is located 0 bytes after 4-byte region [0x6020000000d0,0x6020000000d4)
allocated by thread T0 here:
    #0 0x00010527d164 in malloc+0x78 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x41164)
    #1 0x0001049a0a68 in hello address.c:19
    #2 0x0001049a117c in main address.c:69
    #3 0x00018bd93da0 in start+0x1b4c (dyld:arm64e+0x1fda0)

SUMMARY: AddressSanitizer: heap-buffer-overflow address.c:21 in hello
Shadow bytes around the buggy address:
  0x601ffffffe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x601ffffffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x601fffffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x601fffffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x602000000000: fa fa fd fa fa fa fd fd fa fa fd fd fa fa 00 06
=>0x602000000080: fa fa 00 04 fa fa 00 00 fa fa[04]fa fa fa fa fa
  0x602000000100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000300: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==10999==ABORTING
fish: Job 1, './address_asan AAAAAAAAAAAAAAA …' terminated by signal SIGABRT (Abort)
```

### 2.2 ThreadSanitizer (TSan)

Multi-threading and synchronization is not trivial either.  The
ThreadSanitizer, enabled with `-fsanitize=thread`, is able to detect data races
and other threading-related issues.

Consider the program `thread.c` (some of you might find it familiar) and
observe the inconsistent output:
```bash
$ ./thread 10000 40
there are 1220 primes up to 10000
$ ./thread 10000 40
there are 1202 primes up to 10000
$ ./thread 10000 40
there are 1209 primes up to 10000
```

Use TSan to detect the problems in the code.
```bash
$ ./thread_tsan 10000 40
==================
WARNING: ThreadSanitizer: data race (pid=11307)
  Read of size 8 at 0x00016cf42c90 by thread T3:
    #0 thread_function thread.c:33 (thread_tsan:arm64+0x100000650)

  Previous write of size 8 at 0x00016cf42c90 by thread T2 (mutexes: write M0):
    #0 thread_function thread.c:36 (thread_tsan:arm64+0x10000067c)

  Location is stack of main thread.

  Mutex M0 (0x00016cf42c98) created at:
    #0 pthread_mutex_init <null> (libclang_rt.tsan_osx_dynamic.dylib:arm64e+0x35070)
    #1 main thread.c:60 (thread_tsan:arm64+0x1000007c4)

  Thread T3 (tid=5207684, running) created by main thread at:
    #0 pthread_create <null> (libclang_rt.tsan_osx_dynamic.dylib:arm64e+0x335b8)
    #1 main thread.c:69 (thread_tsan:arm64+0x100000838)

  Thread T2 (tid=5207683, finished) created by main thread at:
    #0 pthread_create <null> (libclang_rt.tsan_osx_dynamic.dylib:arm64e+0x335b8)
    #1 main thread.c:69 (thread_tsan:arm64+0x100000838)

SUMMARY: ThreadSanitizer: data race thread.c:33 in thread_function
==================
there are 1229 primes up to 10000
ThreadSanitizer: reported 1 warnings
fish: Job 1, './thread_tsan 10000 40' terminated by signal SIGABRT (Abort)
```

### 2.3 UndefinedBehaviorSanitizer (UBSan)

Undefined behavior can occur when a C program violates a rule given by the C
language standard and the standard does not specify what should happen in this
cases.
Then the compiler is allowed to do as it pleases.

This can be used to generate faster code: The compiler is allowed to assume
that certain invalid things do not happen and can then optimize the code based
on these assumptions

Consider the program `undefined.c` and follow the comments in the file.  Use
UBSan, enabled with `-fsanitize=undefined`, to detect possible issues.
```bash
$ ./undefined 36 6
36
6
no overflow happened :)
42
success
p = 0x7ffd33643991
s = 328350
```

The following articles give a good introduction to the concept of undefined behavior:

- [John Regehr, A Guide to Undefined Behavior in C and C++](https://blog.regehr.org/archives/213)
- [Chris Lattner, What Every C Programmer Should Know About Undefined Behavior](https://blog.llvm.org/2011/05/what-every-c-programmer-should-know.html)



## 3. Fuzzing

Install [American Fuzzy Lop (AFL)](https://lcamtuf.coredump.cx/afl/) (or its
successor project [AFL++](https://aflplus.plus/)) and `gcc-multilib`:
```
$ sudo apt install afl gcc-multilib
```

In the directories `random_password` and `broken_register` you find two
programs with corresponding Makefiles.  Use AFL to find crashing inputs.  E.g.,
you can use `afl-gcc-fast` (instead of `gcc`) to compile executables with
instrumentation and `afl-fuzz` to perform the actual fuzzing.


### Bonus: Exploit the Programs

If you are ~~bored~~want a challenge, you can try to exploit the two programs
at home.  These are non-trivial, though, and at least `random_password`
requires concepts that we did not discuss in class.  Goal is to print
`flag.txt` or to get a shell.
