# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import sys
import os
import glob
import zlib
import struct
import binascii
import traceback
from os.path import curdir
from pathlib import Path

import zstandard as zstd
from typing import Optional, Callable

MAGIC_NO_COMPRESS_START = 0x03
MAGIC_NO_COMPRESS_START1 = 0x06
MAGIC_NO_COMPRESS_NO_CRYPT_START = 0x08
MAGIC_COMPRESS_START = 0x04
MAGIC_COMPRESS_START1 = 0x05
MAGIC_COMPRESS_START2 = 0x07
MAGIC_COMPRESS_NO_CRYPT_START = 0x09

MAGIC_SYNC_ZSTD_START = 0x0A
MAGIC_SYNC_NO_CRYPT_ZSTD_START = 0x0B
MAGIC_ASYNC_ZSTD_START = 0x0C
MAGIC_ASYNC_NO_CRYPT_ZSTD_START = 0x0D

MAGIC_END = 0x00

lastseq = 0

# RET_OK = (0, 'SUCCESS')
# RET_FAIL = (-1, 'FAILED')
RET_OK = 0
RET_FAIL = -1


def IsGoodLogBuffer(_buffer, _offset, count):
    if _offset == len(_buffer):
        return True, ''

    magic_start = _buffer[_offset]
    if MAGIC_NO_COMPRESS_START == magic_start or MAGIC_COMPRESS_START == magic_start or MAGIC_COMPRESS_START1 == magic_start:
        crypt_key_len = 4
    elif (MAGIC_COMPRESS_START2 == magic_start or MAGIC_NO_COMPRESS_START1 == magic_start
          or MAGIC_NO_COMPRESS_NO_CRYPT_START == magic_start or MAGIC_COMPRESS_NO_CRYPT_START == magic_start
          or MAGIC_SYNC_ZSTD_START == magic_start or MAGIC_SYNC_NO_CRYPT_ZSTD_START == magic_start
          or MAGIC_ASYNC_ZSTD_START == magic_start or MAGIC_ASYNC_NO_CRYPT_ZSTD_START == magic_start):
        crypt_key_len = 64
    else:
        # return False, '_buffer[%d]:%d != MAGIC_NUM_START'%(_offset, _buffer[_offset])
        return False, '_buffer[{}]:{} != MAGIC_NUM_START'.format(_offset, _buffer[_offset])

    headerLen = 1 + 2 + 1 + 1 + 4 + crypt_key_len

    if _offset + headerLen + 1 + 1 > len(_buffer):
        # return (False, 'offset:%d > len(buffer):%d'%(_offset, len(_buffer)))# 旧写法
        # return False, 'offset:{} > len(buffer):{}'.format(_offset, len(_buffer))
        return False, f'offset:{_offset} > len(buffer):{len(_buffer)}'
    read_offset = _offset + headerLen - 4 - crypt_key_len
    length = struct.unpack_from("I", _buffer, read_offset)[0]
    end_pos = _offset + headerLen + length + 1
    if end_pos > len(_buffer):
        return False, f'log length:{length}, end pos {end_pos} > len(buffer):{len(_buffer)}'
    if MAGIC_END != _buffer[_offset + headerLen + length]:
        return False, 'log length:{}, buffer[{}]:{} != MAGIC_END'.format(length, _offset + headerLen + length,
                                                                         _buffer[_offset + headerLen + length])
        # return False, (f'log length:{length}, buffer[{_offset + headerLen + length}]'
        #                f':{_buffer[_offset + headerLen + length]} != MAGIC_END')

    if 1 >= count:
        return True, ''
    else:
        return IsGoodLogBuffer(_buffer, _offset + headerLen + length + 1, count - 1)


def GetLogStartPos(_buffer, _count):
    offset = 0
    while True:
        if offset >= len(_buffer):
            break

        # PEP8规范：尽量避免使用反斜杠续行，优先括号隐式换行
        if (MAGIC_NO_COMPRESS_START == _buffer[offset] or MAGIC_NO_COMPRESS_START1 == _buffer[offset]
                or MAGIC_COMPRESS_START == _buffer[offset] or MAGIC_COMPRESS_START1 == _buffer[offset]
                or MAGIC_COMPRESS_START2 == _buffer[offset] or MAGIC_COMPRESS_NO_CRYPT_START == _buffer[offset]
                or MAGIC_NO_COMPRESS_NO_CRYPT_START == _buffer[offset] or MAGIC_SYNC_ZSTD_START == _buffer[offset]
                or MAGIC_SYNC_NO_CRYPT_ZSTD_START == _buffer[offset] or MAGIC_ASYNC_ZSTD_START == _buffer[offset]
                or MAGIC_ASYNC_NO_CRYPT_ZSTD_START == _buffer[offset]):
            if IsGoodLogBuffer(_buffer, offset, _count)[0]:
                return offset
        offset += 1

    return -1


def DecodeBuffer(_buffer, _offset, _outbuffer):
    if _offset >= len(_buffer): return -1
    # if _offset + 1 + 4 + 1 + 1 > len(_buffer): return -1
    ret = IsGoodLogBuffer(_buffer, _offset, 1)
    if not ret[0]:
        fixpos = GetLogStartPos(_buffer[_offset:], 1)
        if -1 == fixpos:
            return -1
        else:
            _outbuffer.extend("[F]decode_log_file.py decode error len={}, result:{} \n".format(fixpos, ret[1]))
            _offset += fixpos

    magic_start = _buffer[_offset]
    if (MAGIC_NO_COMPRESS_START == magic_start or MAGIC_COMPRESS_START == magic_start or MAGIC_COMPRESS_START1
            == magic_start):
        crypt_key_len = 4
    elif (MAGIC_COMPRESS_START2 == magic_start or MAGIC_NO_COMPRESS_START1 == magic_start
          or MAGIC_NO_COMPRESS_NO_CRYPT_START == magic_start or MAGIC_COMPRESS_NO_CRYPT_START == magic_start
          or MAGIC_SYNC_ZSTD_START == magic_start or MAGIC_SYNC_NO_CRYPT_ZSTD_START == magic_start
          or MAGIC_ASYNC_ZSTD_START == magic_start or MAGIC_ASYNC_NO_CRYPT_ZSTD_START == magic_start):
        crypt_key_len = 64
    else:
        _outbuffer.extend(f'in DecodeBuffer _buffer[{_offset}]:{magic_start} != MAGIC_NUM_START')
        return -1

    headerLen = 1 + 2 + 1 + 1 + 4 + crypt_key_len
    length = struct.unpack_from("I", _buffer, _offset + headerLen - 4 - crypt_key_len)[0]
    tmpbuffer = bytearray(length)

    seq = struct.unpack_from("H", _buffer, _offset + headerLen - 4 - crypt_key_len - 2 - 2)[0]
    begin_hour = struct.unpack_from("c", _buffer, _offset + headerLen - 4 - crypt_key_len - 1 - 1)[0]
    end_hour = struct.unpack_from("c", _buffer, _offset + headerLen - 4 - crypt_key_len - 1)[0]

    global lastseq
    if seq != 0 and seq != 1 and lastseq != 0 and seq != (lastseq + 1):
        _outbuffer.extend("[F]decode_log_file.py log seq:{}-{} is missing\n".format(lastseq + 1, seq - 1))

    if seq != 0:
        lastseq = seq

    tmpbuffer[:] = _buffer[_offset + headerLen:_offset + headerLen + length]

    try:
        if (MAGIC_NO_COMPRESS_START1 == _buffer[_offset] or MAGIC_COMPRESS_START2 == _buffer[_offset]
                or MAGIC_SYNC_ZSTD_START == _buffer[_offset] or MAGIC_ASYNC_ZSTD_START == _buffer[_offset]):
            print("use wrong decode script")
        elif MAGIC_ASYNC_NO_CRYPT_ZSTD_START == _buffer[_offset]:
            # decompressor = zstd.ZstdDecompressor()
            # tmpbuffer = next(decompressor.read_from(ZstdDecompressReader(str(tmpbuffer)), 100000, 1000000))
            decompressor = zstd.ZstdDecompressor()
            tmpbuffer = decompressor.decompress(tmpbuffer)
        elif MAGIC_COMPRESS_START == _buffer[_offset] or MAGIC_COMPRESS_NO_CRYPT_START == _buffer[_offset]:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            tmpbuffer = decompressor.decompress(tmpbuffer)
        elif MAGIC_COMPRESS_START1 == _buffer[_offset]:
            decompress_data = bytearray()
            while len(tmpbuffer) > 0:
                single_log_len = struct.unpack_from("H", tmpbuffer, 0)[0]
                decompress_data.extend(tmpbuffer[2:single_log_len + 2])
                tmpbuffer[:] = tmpbuffer[single_log_len + 2:len(tmpbuffer)]

            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            tmpbuffer = decompressor.decompress(decompress_data)
        else:
            pass

            # _outbuffer.extend('seq:%d, hour:%d-%d len:%d decompress:%d\n' %(seq, ord(begin_hour), ord(end_hour), length, len(tmpbuffer)))
    except Exception as e:
        traceback.print_exc()
        _outbuffer.extend("[F]decode_log_file.py decompress err, {}\n".format(str(e)))
        return _offset + headerLen + length + 1

    _outbuffer.extend(tmpbuffer)

    return _offset + headerLen + length + 1


def ParseFile(_file, _outfile):
    try:
        with open(_file, 'rb') as fp:
            _buffer = bytearray(os.path.getsize(_file))
            fp.readinto(_buffer)

        startpos = GetLogStartPos(_buffer, 2)
        if -1 == startpos:
            return RET_FAIL, "源文件异常：找不到查找文件起始位置"

        outbuffer = bytearray()
        while True:
            startpos = DecodeBuffer(_buffer, startpos, outbuffer)
            if -1 == startpos:
                break

        if 0 == len(outbuffer):
            return RET_FAIL, "解压异常"

        with open(_outfile, 'wb') as fpout:
            size = fpout.write(outbuffer)
            return size, f'解析成功，文件大小：{size}'
    except FileNotFoundError:
        return RET_FAIL, f"错误：输入文件不存在 {_file}"
    except Exception as e:
        return RET_FAIL, f"未知异常：{str(e)}"


'''
@:param src: source files or a directory of sources
@:param dest: file path. only support existed dir or empty value.
@:param callback: callback function
'''


def depress(src: list[str] | None = None, dest='', callback: Optional[Callable[[str], None]] = None):
    if src is None:
        src = []



    # 支持场景
    # 源文件参数4种情况，分别是目录，单个和多个日志文件，空
    # 目的文件2种情况，分别是目录，和空

    # if callable(callback):
    #     log = callback
    # else:
    #     def log(msg: str) -> None:
    #         pass

    log = callback if callable(callback) else lambda message: None
    result = []
    if not os.path.isdir(dest):
        log(f'warning: {dest} does not exist')
        dest = os.getcwd()

    size = len(src)
    if 1 == size:
        # 选时，可能是个文件或目录。
        path: str = src[0]
        log(f'ParseFile: path={path}')
        if os.path.isfile(path):
            # 单个文件
            outfile = os.path.join(dest, os.path.basename(path) + '.log')
            ret, msg = ParseFile(path, outfile)
            result.append((ret, msg))
            log(f'ParseFile: src={path}, dest={outfile}, result={ret}, {msg}')
        else:
            # 非目录转成当前目录
            if not os.path.isdir(path):
                path = os.getcwd()
                log(f'warning: {path} does not exist')
            filelist = glob.glob(os.path.join(path, '*.log'))
            for infile in filelist:
                outfile = os.path.join(dest, os.path.basename(infile) + '.log')
                ret, msg = ParseFile(infile, outfile)
                result.append((ret, msg))
                log(f'ParseFile: src={infile}, dest={outfile}, result={ret}, {msg}')

    elif size > 1:
        # 多选时，一定是多个文件，不会有目录出现。
        log(f'ParseFile size: {size}')
        for infile in src:
            if os.path.isfile(infile):
                outfile = os.path.join(dest, os.path.basename(infile) + '.log')
                ret, msg = ParseFile(infile, infile)
                log(f'ParseFile: src={infile}, dest={outfile}, result={ret}, {msg}')
                result.append((ret, msg))
            else:
                log(f'ParseFile: {infile} isn\'t file')
    else:
        # 空
        log(f'Warning: source file does not exist')
        path = os.path.abspath(".")
        filelist = glob.glob(os.path.join(path, '*.log'))
        log(f'ParseFile Current directory {path}: *.xlog, size={len(filelist)}')
        for infile in filelist:
            outfile = os.path.join(dest, os.path.basename(infile) + '.log')
            ret, msg = ParseFile(infile, outfile)
            result.append((ret, msg))
            log(f'ParseFile: src={infile}, dest={outfile}, result={ret}, {msg}')
    return result

def parse_dir(_dir: list[str], _out_dir: str, callback: Optional[Callable[[str], None]]):
    for _infile in _dir:
        parse_file(_infile, _out_dir, callback)
        # _outfile = os.path.join(_out_dir, os.path.basename(_infile) + '.log')
        # _ret, _msg = ParseFile(_infile, _outfile)
        # callback(f'ParseFile: src={_infile}, dest={_outfile}, result={_ret}, {_msg}')

def parse_file(_infile: str, _out_dir: str, callback: Optional[Callable[[str], None]]):
    _outfile = os.path.join(_out_dir, os.path.basename(_infile) + '.log')
    _ret, _msg = ParseFile(_infile, _outfile)
    callback(f'ParseFile: src={_infile}, dest={_outfile}, result={_ret}, {_msg}')


def main(args):
    global lastseq
    if 1 == len(args):
        path = args[0]
        if os.path.isdir(path):
            filelist = glob.glob(os.path.join(path, "*.log"))
            for filepath in filelist:
                lastseq = 0
                ParseFile(filepath, filepath + ".log")
        else:
            _filename = args[0]
            outfile = f'{path}.log'
            print('open file=', _filename, '\nout file=', outfile)
            lastseq = 0
            ParseFile(path, outfile)
    elif 2 == len(args):
        ParseFile(args[0], args[1])
    else:
        filelist = glob.glob("*.xlog")
        for filepath in filelist:
            lastseq = 0
            ParseFile(filepath, f"{filepath}.log")


'''
用法1：不带参数。直接运行程序，将解析当前路径下所有.xlog文件
用法2：1个参数，即待解析文件名，无需后缀。例子：py decode_noncrypt.py 待解析文件ABC
用法3:2个参数，即待解析文件和输出文件，无需后缀。例子：py decode_noncrypt.py 待解析 待输出文件123
'''
if __name__ == "__main__":
    main(sys.argv[1:])

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
