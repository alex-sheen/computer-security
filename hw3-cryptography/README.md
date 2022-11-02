# Assignment 3, Part 2: Cryptography

In this part of Assignment 3 you'll experiment with hash functions.  You'll learn about length extension attacks and implement your own attack against a simulated web app. Finally you'll use the actual collision-finding attack against MD5 to see how malicious programs can exploit MD5.


## Tech Set-Up
The following files are provided in `assignment3-part2.tar`:
- `assignment3.py`: This contains skeleton code. You will implement
`problem1()` here. This includes an implementation of `make_query()`
for accessing the server in Problem 1.
- `pymd5.py`: A purely Python implementation of the MD5 hash function, used in Problem 2.
- `problem1_example.py`: An example of a length extension attack against MD5.
- `Makefile`: This is for building `fastcoll` in Problem 2.



## Problem 1: Length Extension Attacks (35 points)

### Introduction

In lecture we briefly saw that constructing a MAC from a hash function
is a delicate task. A common insecure construction is
```
    MAC(K,M) := H(K+M),
```
where "+" is string concatenation. This fails even if the key is large
and the hash function ``H`` is reasonably secure. In this problem,
we'll take the hash to be MD5, which is insecure and should be not be used.
(We use MD5 here for two reasons: First, a good Python library is available.
Second, secure hashes like SHA256 are vulnerable to the same attack, so
the lesson is the same.)

This construction is vulnerable to a so-called *length extension attack*, which we explain in detail shortly. It is based on the following principle: Due to the way the MD5 algorithm works, it is possible for someone to take the hash `h` of an unknown message `X` and compute the hash of `X+S` where `S` is a string mostly under their control. That is, given the value
```
MD5(X)
```
one can compute the value
```
MD5(X+S)
```
*without knowing `X`*! This leads to a MAC forgery: Given the output `t=MAC(K,M)=MD5(K+M)`, one can compute `t'=MAC(K,M+S)=H(K+M+S)` for some partially-chosen string `S`, and this will be accepted as valid. (Here, we took `X=K+M`.)

An untold number of systems have fallen to this attack. A famous example
is a 2009 attack against Flickr (see [here](http://netifera.com/research/flickr_api_signature_forgery.pdf)). 


### Background: How MD5 works 

To begin understanding length extension attacks, we need to look at
how MD5 is structured.
Internally, MD5 works as follows on an input
`X`.  It first performs some pre-processing:
1. Let `L` be the bit-length of `X`.
2. Break `X` into 512-bit blocks, leaving the last block possibly less than 512 bits.
3. Pad the last block up to 512 bits by appending a 1 bit, then
        the appropriate number of zero bits, then a 64-bit encoding of
        `L`. If the last block had fewer than 65 bits of space left,
        add a new 512-bit block.

Now let `X'[1]`, `X'[2]`, ..., `X'[n]` be the 512-bit blocks of the
preprocessed message. To compute the output hash, MD5 initializes a
128-bit state `s` to a default value, and then computes
```
for i = 1,...,n:
    s = f(s,X'[i]) 
```
where `f` some function that outputs 128 bits (called the *compression function*). The final output is `s`. Intuitively, `s` is an internal "state", and MD5 is chomping up the blocks of (padded) input and updated the state. You can check out how the compression function works on [Wikipedia](https://en.wikipedia.org/wiki/MD5), but it will not be needed for this assignment.

### Background: Length-extension attacks 

Suppose you have the final output `s` of MD5, computed for some input `X`. There's nothing stopping you for computing `f(s,y)` for your chosen block `y`, and indeed from continuing with more blocks (the function `f` is publicly known and it does not take a secret key as input). If you do this, and are careful about padding, you'll have the MD5 hash of the original message plus a suffix.

Take a minute to examine exactly what message the resulting digest corresponds to after performing this attack for one step. The state output `s` corresponds to evaluating MD5 on some message, and that means the message was padded. If we start using `s`, it means the "message" will now contain the padding that was previously added, and we have to pad again. You can see this show up in the example attack below.

### Background: Running a length-extension attack 

A Python implementation of MD5 is given in the included file `pymd5.py`. If you open up this file, `md5_compress` plays the role of `f`. The function `padding` takes an integer as input, and returns the correct padding for message with that bit-length (i.e. a 1 followed by the correct number of zeros). The file has further documentation at the top.

An example attack is given in the included file `problem1_example.py`. Note that the MD5 implementation gives an object that you can "update" many times before asking for the current digest. Internally, this changes the state and counter (of the number of bits processed so far). In the example attack, we use feature that allows us to set the state and counter ourselves (this is the `md5(state=...)` line). Note the tricky step, where we reuse a previous state but set the counter to larger value. This effectively turns the previous padding bits into message bits.


### Your task: Attack FlickUr. 

In this part, you will carry out a simplified version of the Flickr attack
against a new and improved, but still insecure, service called Flick*Ur*. You will use the oracle to obtain a URL which contains a MAC tag computed using the vulnerable MD5 construction. You should write code that modifies the URL to have an additional parameter (giving you admin access), along with a modified tag that will be accepted by the server.

Calling the `make_query(cnetid,"")` will return
a URL of the form
```
http://www.flickur.com/?api_tag=<md5-digest>&uname=<your-cnetid>&role=user
```
The MD5 digest is computed by the server as
```
MD5(<secret-key> + <rest of url after first ampersand>)
```
 where "+" is string concatenation and
`<secret-key>` is a secret string of unknown length.
More concretely, for this URL, the digest is
```
MD5(<secret-key> + uname=<your-cnetid>&role=user).
```
Constructs like this are sometimes used to keep a user "logged in" to a web app. We will learn more about this when we study web security.


If you call the `make_query` with second argument a non-empty string, 
then it will treat that string
as a URL. It will check that the domain is correct, and parse out the `api_tag`
and the rest of the URL. It will attempt to verify if `api_tag` is correct
for the URL you submitted. If you have the correct token, and your string
contains the `&role=admin`, then it will return success. If your token is
correct but the you don't have the role `admin`, it will return ``ok``. If
your `api_tag` is incorrect then you will receive an error message. You can
have the role assigned multiple times in your URL, and the server will also
(unrealistically) tolerate NULL bytes in the URL.

Note that this oracle is returning and accepting the entire URL as input.
This URL is not actually loaded, and we don't own `flickur.com`. It's just
for fun.

In your code file, should implement a function `problem1()` that retrieves the initial URL and returns a modified URL that causes the oracle to return success. (Your function does not need to call the oracle with the modified URL, but it may. It should return the URL in any case.) Both the original URL and your modified URL should have your CNetID. For testing, your code should be robust to changes in the secret length (say up to 64 bytes long). For your testing, here is the code that the server is running (without telling you what the secret key is):
```c
KEY1 = binascii.unhexlify(secret)

def response_logic(cnet, query=''):
    
    if len(query) == 0:
        h = md5()
        msg = KEY1 + b'uname=' + cnet + b'&role=user'
        h.update(msg)
        digest = h.hexdigest()
        url = ("http://www.flickur.com/?api_tag={md5_digest}"
               "&uname={cnet}&role=user").format(md5_digest=digest, 
               cnet=cnet.decode('utf-8'))
        response = bytes(url, 'utf-8')
        return response

    else:
        if not query.startswith(b'http://www.flickur.com/?'):
            return b'Invalid URL'

        params_strs = query.lstrip(b'http://www.flickur.com/?')
        ps = list(map(lambda x: x.split(b'='), params_strs.split(b'&')))
        params = {p[0]: p[1] for p in ps if len(p) >= 2}

        amp_index = params_strs.find(b'&')
        msg = KEY1 + params_strs[amp_index+1:]
        h = md5()
        h.update(msg)

        if h.hexdigest() == params[b'api_tag'].decode('utf-8'):
            if params[b'role'] == b'admin':
                return b"Admin Login Success!"
            else:
                return b'OK'
        else:
            return b'Incorrect hash'
```
You may want to call this function directly instead of `make_query` while debugging. (Just set `secret` to some hex characters.)

### Deliverables for Problem 1

Your code file should contain your implementation of `problem1`. 

In your write-up, briefly describe any ideas or techniques that you used in
your solution (beyond those described above) to make the attack work.

## Problem 2: Exploiting MD5 Collisions (25 points total)

### MD5 Warm-Up (0 points)

The first collision in MD5 was famously published in 2004 by Xiaoyun Wang,
Dengguo Feng, Xuejia Lai, and Hongbo Yu. Here is an example of a pair of
hex-encoded messages that collide under MD5:
```
4a60143d787a8c99b0efa2b9792d35fee5af44968d4e0910576241ce8a98
bc3773b1facadec7ab17671c681c36ec4c47362ad2908a333c8dd53731c4
01518ad92a1561397e5737a67ea94cf98a6e03f752d063279d01b72c0a1d
6616ce6ad5bdfd07f75a60308f261a9e0d329f38fe5cd908055197d0f35c
c7301a6cbfea577c
```
and
```
4a60143d787a8c99b0efa2b9792d35fee5af44168d4e0910576241ce8a98
bc3773b1facadec7ab17671c681c366c4d47362ad2908a333c8dd5373144
01518ad92a1561397e5737a67ea94cf98a6e03f752d063a79d01b72c0a1d
6616ce6ad5bdfd07f75a60308f261a9e0d329fb8fd5cd908055197d0f35c
c7301aecbfea577c
```

As a warm-up, check that these messages actually collide under MD5. To
do this, you first need to copy the hex strings to files (say `f1.hex`
and `f2.hex`). Next you need to decode them from hex to binaries. (Note that "binaries" is common parlance for "files consisting of mostly
non-printable characters." So binaries look like mostly junk if you open them in a text editor. The term does not mean "binary numbers" or
similar.}. 
You
can do this by running 
```
xxd -r -p hex_file > binary_file 
```
You
can then print the MD5 digests either using the Python3 code from the
first problem, or using OpenSSL at the command line via
```
openssl dgst -md5 binary_file1 binary_file2
```
In either case you should
get the same output twice.

For completeness, try hashing some two files and observing that they do not
output the same MD5 hash (using the same `openssl` command). Also, try
changing `-md5` to `-sha256` and observe two things: Even when files collide
MD5, they do not collide SHA256, and also that the SHA256 output is longer.

There is nothing to submit for this part.

### 2a: Generating Your Own MD5 Collision (10 points)

Now you'll generate your very own collision in MD5. 
The original attack has been
honed into a practical collision-finding attack allowing for
*chosen-prefix* collisions. This means that you can specify any string
`prefix` and quickly find two (binary) strings `msg1` and
`msg2` such that 
`MD5(prefix + msg1)` equals
`MD5(prefix + msg2)`, where "+" denotes string concatenation.  The
strings `msg1` and `msg2` are still out of your control (as the attack will
need to choose them in a specific way), so this may still not see so
threatening. We will return to this issue in the next part.

For this part you will need to install a program called `fastcoll`
for finding MD5 collisions. This software was written by a cryptographer
named Marc Stevens (who also was part of the team that found the first SHA-1
collision).

The software source is available [here](http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5-1_source.zip), and a Windows executable is available
[here](http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip).

If compiling from source on MacOS or Linux, you will need to install the
[Boost](https://en.wikipedia.org/wiki/Boost_(C\%2B\%2B_libraries)) package. If you are working on a department Linux machine, Boost is probably already installed.  On MacOS, you can run `brew install boost`, and on Linux you can use the appropriate package manager to install `libboost-all-dev` (for example, if you're using the class VM, you can run `sudo apt-get install libboost-all-dev`; This will download about 250MB.).

To compile `fastcoll`, you can use its included makefile. In that Makefile, you need
to set the path to your boost libraries and header files. On my Mac,
these were in `/usr/local/Cellar/boost/1.56.0/lib`
and `/usr/local/Cellar/boost/1.56.0/include` respectively.

Once you have `fastcoll` running, you can invoke it with the syntax
`fastcoll -p prefixfile -o msg1.bin msg2.bin`. This will output
(binary) collisions in the `.bin` files, both of which start with the
contents of `prefixfile`.

### Your task, and what to submit

For this part, generate a pair of colliding files that start with your CNetID (in ASCII), and time how long it takes (e.g. `time fastcoll -p ...`). Name the files containing your collision as `<YOUR CNETID>-2a-1.bin` and `<YOUR CNETID>-2a-2.bin`. As usual, replace `<YOUR CNETID>` with your CNetID. For example, David would submit files named `davidcash-2a-1.bin` and `davidcash-2a-2.bin`. They will be submitted on Canvas (see the end of this assignment).

You will also a submit a write-up with responses for each problem.
In your write-up include the following for Problem 1:

1. Use `xxd -p` to get a hex encoding of your files, and include 
        them in your assignment write-up.
2. The MD5 hashes (in hex) of your files and the SHA256 hashes (in hex) of your files.
3. In your write-up, say how long it took your computer to find a
        collision (as reported by `time`, or equivalent).

### 2b: Generating Your Own *Malicious* MD5 Collision (15 points)

Now let's see how MD5 collisions are exploited to create programs that
have identical hashes but different behavior. To do this, we'll combine
the two concepts we've seen so far: We start by fixing a program fragment
`prefix`, then run `fastcoll`, which gives us two binary
blobs `blob1` and `blob2`; We now know that
the MD5 hash of `prefix + blob1` is the same
as that of `prefix + blob2`. When this is true, we *also* know that for any
program fragment `suffix`,
```
        MD5(prefix + blob1 + suffix) =
        MD5(prefix + blob2 + suffix)
```
(Note here we're not doing a length extension attack; This is just a simple
property of MD5 that follows from the structure described in the previous
problem.)

For this problem, use this approach to create two programs with the same MD5
hash. The first program should output "`my name is cnetid, and i am good`",
while the second program should output "`my name is cnetid, and i am evil`",
where again you replace `cnetid` with your own. You are free to use any
programming language to create your files, but the programs you submit should
run on typical Linux machines. You may write out files, but please also don't
do anything nasty to the machine running your program.

Here is how I solved this problem; You are free to use other techniques (but
please ask us if you're doing something that might not work when we run it).
A moment's thought reveals that we need a programming language that will
tolerate a binary blob in the middle of source file. Most languages won't
like this, at least not without some significant trickery. One language
that works is `bash` shell scripting. It's really ugly, really useful,
and happy to process binary garbage!

A specific technique to consider using is called *here-documents*.  Here is
an example.  If you put the following in a file called `text.sh`:
```
    cat << 'EOF' > outfile
    <any bytes>
    EOF
    cat outfile
```
When you run `bash text.sh`, all bytes starting on the second line,
until the line containing only EOF, will be read by the shell and be fed into
standard input for `cat`, which outputs them to `outfile`. (Check the `bash`
manpage for "Here Documents", or
[Wikipedia](https://en.wikipedia.org/wiki/Here_document#Unix_shells) for more
details.) After that, the final line will read those bytes back from the file
and print them. To turn this into a working exploit, you'll need to think
about how to abuse your powers describe above, and learn a little about shell
scripting to do what you want.


#### Deliverables for Problem 2

The deliverables for this part are:
1. Your colliding programs, with the names `<YOUR CNETID>-2b-1` and `<YOUR CNETID>-2b-2`. As usual, replace `<YOUR CNETID>` with your CNetID. For example, David would submit files named `davidcash-2b-1` and `davidcash-2b-2`.
 
In your write-up for this part, including the following:
1. The MD5 hashes (in hex) of your programs.
2. Describe how your programs work. (We should be able to just run them. For
the write-up, we want to see a description of the technique you used.)

## What and How to Submit

Please submit the following to Canvas:

1. Your write-up in a file `<YOUR CNETID>.txt/pdf`, which should contain a responses for:
 - Your responses for Problem 1.
 - Your responses for Problem 2a.
 - Your responses for Problem 2b.
2. Your file `assignment3.py` solving Problem 1.
3. Two files with the names `<YOUR CNETID>-2a-1.bin` and `<YOUR CNETID>-2a-2.bin` that solve Problem 2a.
4. Two files with the names `<YOUR CNETID>-2b-1` and `<YOUR CNETID>-2b-2` that solve Problem 2b.
