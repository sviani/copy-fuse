#!/usr/bin/env python

from __future__ import with_statement

from errno import ENOENT, EIO, EPERM
from stat import S_IFDIR, S_IFREG
from sys import argv, stderr
from threading import Lock
import argparse
import getpass
import hashlib
import json
import os
import time
import urllib3

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn


class CopyAPI:
    headers = {'X-Client-Type': 'api', 'X-Api-Version': '1', "Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}

    def __init__(self, username, password):
        self.auth_token = ''
        self.tree_children = {}
        self.tree_expire = {}
        self.httpconn = urllib3.connection_from_url("https://api.copy.com", block=True, maxsize=1, timeout=30)
        data = {'username': username, 'password' : password}
        response = self.copyrequest('/auth_user', data)
        if 'auth_token' not in response:
            raise FuseOSError(EPERM)
        else:
            self.auth_token = response['auth_token'].encode('ascii', 'ignore')

    def copygetrequest(self, uri, data, return_json=True):
        headers = self.headers
        if self.auth_token != '':
            headers['X-Authorization'] = self.auth_token
        response = self.httpconn.request_encode_body("GET", uri, {}, headers, False)
        if return_json == True:
            return json.loads(response.data, 'latin-1')
        else:
            return response.data

    def copyrequest(self, uri, data, return_json=True):
        headers = self.headers
        if self.auth_token != '':
            headers['X-Authorization'] = self.auth_token
        response = self.httpconn.request_encode_body("POST", uri, {'data': json.dumps(data)}, headers, False)
        if return_json == True:
            return json.loads(response.data, 'latin-1')
        else:
            return response.data

    def part_request(self, method, parts, data=None):
        headers = self.headers
        headers['X-Part-Count'] = len(parts)

        payload = ''

        for i in range(0, len(parts)):
            part_num = str(i + 1)
            headers['X-Part-Fingerprint-' + part_num] = parts[i]['fingerprint']
            headers['X-Part-Size-' + part_num] = parts[i]['size']
            headers['X-Part-Share-' + part_num] = 0

            if method == 'send_parts':
                payload = payload + parts[i]['data']

        # authentication http headers
        if self.auth_token != '':
            headers['X-Authorization'] = self.auth_token

        # print headers

        if method != 'send_parts':
            response = self.httpconn.request_encode_body("POST", "/" + method, {'data': json.dumps(data)}, headers, False)
        else:
            response = self.httpconn.urlopen("POST", "/" + method, payload, headers)

        if method == 'get_parts':
            return response.data
        return json.loads(response.data, 'latin-1')

    def find_part(self, f, offset):
        if f['curr_part'] and int(f['curr_part']['offset']) == offset:
            return f['curr_part']
        part_found = None
        parts = f['object']['object']['revisions'][0]['parts']
        for part in parts:
            lower = int(part['offset'])
            upper = lower + int(part['size'])
            if lower <= offset and offset < upper:
                part_found = part
                break
        return part_found

    def cache_part_data(self, f, part):
        if part != f['curr_part']:
            f['curr_part_data'] = self.part_request("get_parts", [part], None)
            f['curr_part'] = part
        return f['curr_part_data']

    def get_part_data(self, part, data, offset, size):
        lower = offset - int(part['offset'])
        upper = lower + size
        if upper > int(part['size']):
            upper = int(part['size'])
        if lower >= upper:
            return None
        return data[lower:upper]

    def list_objects(self, path, ttl=10):
        # check cache
        if path in self.tree_expire:
            if self.tree_expire[path] >= time.time():
                return self.tree_children[path]

        # obtain data from copy
        # print "listing objects from cloud for path: " + path
        data = {'path': path, 'max_items': 1000000}
        response = self.copyrequest('/list_objects', data)
        if 'children' not in response:
            raise FuseOSError(EIO)

        # build tree
        self.tree_children[path] = {}
        for child in response['children']:
            name = os.path.basename(child['path']).encode('utf8')
            ctime = int(child['created_time'])
            if child['modified_time'] == None:
                mtime = ctime
            else:
                mtime = int(child['modified_time'])
            self.tree_children[path][name] = {'name': name, 'type': child['type'], 'size': child['size'], 'ctime': ctime, 'mtime': mtime}

        # update expiration time
        self.tree_expire[path] = time.time() + ttl

        return self.tree_children[path]

    def partify(self, f, size):
        parts = {}

        part_num = 0
        offset = 0
        while f.tell() < size:
            # obtain the part data
            offset = f.tell()
            part_data = f.read(1048576)
            parts[part_num] = {'fingerprint': hashlib.md5(part_data).hexdigest() + hashlib.sha1(part_data).hexdigest(), 'offset': offset, 'size': len(part_data), 'data': part_data}
            offset = f.tell()
            part_num += 1

        if size != offset:
            # print str(size) + " != " + str(offset)
            raise FuseOSError(EIO)

        return parts

class CopyFUSE(LoggingMixIn, Operations):
    def __init__(self, username, password, logfile=None):
        self.rwlock = Lock()
        self.copy_api = CopyAPI(username, password)
        self.logfile = logfile
        self.files = {}

    def file_rename(self, old, new):
        if old in self.files:
            self.files[new] = self.files[old]
            del self.files[old]

    def file_get(self, path):
        if path in self.files:
            return self.files[path]
        data = {'path': path, 'max_items': 1, 'include_parts': 1}
        obj = self.copy_api.copyrequest('/list_objects', data)
        self.files[path] = {'object': obj, 'modified': False, 'curr_part': None, 'curr_part_data': None}
        return self.files[path]

    def file_close(self, path):
        if path in self.files:
            if self.files[path]['modified'] == True:
                self.file_upload(path)
            del self.files[path]

    def file_upload(self, path):
        # TODO
        pass

    def chmod(self, path, mode):
        return 0

    def chown(self, path, uid, gid):
        return 0

    def statfs(self, path):
        params = {}
        response = self.copy_api.copygetrequest('/rest/user', params, True)
        # blocks = response["storage"]["used"] / 512
        bavail = response["storage"]["quota"] / 512
        bfree = (response["storage"]["quota"] - response["storage"]["used"]) / 512
        return dict(f_bsize=512, f_frsize=512, f_blocks=bavail, f_bfree=bfree, f_bavail=bfree)

    def getattr(self, path, fh=None):
        # print "getattr: " + path
        if path == '/':
            st = dict(st_mode=(S_IFDIR | 0755), st_nlink=2)
            st['st_ctime'] = st['st_atime'] = st['st_mtime'] = time.time()
        else:
            name = str(os.path.basename(path))
            objects = self.copy_api.list_objects(os.path.dirname(path))

            if name not in objects:
                raise FuseOSError(ENOENT)
            elif objects[name]['type'] == 'file':
                st = dict(st_mode=(S_IFREG | 0644), st_size=int(objects[name]['size']))
            else:
                st = dict(st_mode=(S_IFDIR | 0755), st_nlink=2)

            st['st_ctime'] = st['st_atime'] = objects[name]['ctime']
            st['st_mtime'] = objects[name]['mtime']

        st['st_uid'] = os.getuid()
        st['st_gid'] = os.getgid()
        return st

    def mkdir(self, path, mode):
        # print "mkdir: " + path
        # send file metadata
        params = {'meta': {}}
        params['meta'][0] = {'action': 'create', 'object_type': 'dir', 'path': path}
        response = self.copy_api.copyrequest('/update_objects', params, True)

        # trap any errors
        if response['result'] != 'success':
            raise FuseOSError(EIO)

        # update tree_children
        name = os.path.basename(path)
        self.copy_api.tree_children[os.path.dirname(path)][name] = {'name': name, 'type': 'dir', 'size': 0, 'ctime': time.time(), 'mtime': time.time()}

    def open(self, path, flags):
        # print "open: " + path
        self.file_get(path)
        return 0

    def flush(self, path, fh):
        # print "flush: " + path
        if path in self.files:
            if self.files[path]['modified'] == True:
                self.file_upload(path)

    def fsync(self, path, datasync, fh):
        # print "fsync: " + path
        if path in self.files:
            if self.files[path]['modified'] == True:
                self.file_upload(path)

    def release(self, path, fh):
        # print "release: " + path
        self.file_close(path)

    def read(self, path, size, offset, fh):
        buf = ""
        f = self.file_get(path)
        while size > 0:
            # print "*** offset = " + repr(offset) + " size = " + repr(size) + " len(buf) = " + repr(len(buf))
            part = self.copy_api.find_part(f, offset)
            # print "*** part = " + repr(part)
            if part == None:
                break
            data = self.copy_api.cache_part_data(f, part)
            chunk = self.copy_api.get_part_data(part, data, offset, size)
            if chunk == None:
                break
            buf += chunk
            offset += len(chunk)
            size -= len(chunk)
        return buf

    def readdir(self, path, fh):
        # print "readdir: " + path
        objects = self.copy_api.list_objects(path)

        listing = ['.', '..']
        for child in objects:
            listing.append(child)
        return listing

    def rename(self, old, new):
        # print "renaming: " + old + " to " + new
        self.file_rename(old, new)
        params = {'meta': {}}
        params['meta'][0] = {'action': 'rename', 'path': old, 'new_path': new}
        self.copy_api.copyrequest("/update_objects", params, False)

    def create(self, path, mode):
        # print "create: " + path
        name = os.path.basename(path)
        if os.path.dirname(path) in self.copy_api.tree_children:
            self.copy_api.tree_children[os.path.dirname(path)][name] = {'name': name, 'type': 'file', 'size': 0, 'ctime': time.time(), 'mtime': time.time()}
        self.file_get(path)
        self.file_upload(path)
        return 0

    def truncate(self, path, length, fh=None):
        # print "truncate: " + path
        f = self.file_get(path)['object']
        f.truncate(length)

    def unlink(self, path):
        # print "unlink: " + path
        params = {'meta': {}}
        params['meta'][0] = {'action': 'remove', 'path': path}
        self.copy_api.copyrequest("/update_objects", params, False)

    def rmdir(self, path):
        params = {'meta': {}}
        params['meta'][0] = {'action': 'remove', 'path': path}
        self.copy_api.copyrequest("/update_objects", params, False)

    def write(self, path, data, offset, fh):
        fileObject = self.file_get(path)
        # TODO
        fileObject['modified'] = True
        return len(data)

    # Disable unused operations:
    access = None
    getxattr = None
    listxattr = None
    opendir = None
    releasedir = None

def main():
    parser = argparse.ArgumentParser(
        description='Fuse filesystem for Copy.com')

    parser.add_argument(
        '-d', '--debug', default=False, action='store_true',
        help='turn on debug output (implies -f)')
    parser.add_argument(
        '-s', '--nothreads', default=False, action='store_true',
        help='disallow multi-threaded operation / run with only one thread')
    parser.add_argument(
        '-f', '--foreground', default=False, action='store_true',
        help='run in foreground')
    parser.add_argument(
        '-o', '--options', help='add extra fuse options (see "man fuse")')

    parser.add_argument(
        'username', metavar='EMAIL', help='username/email')
    parser.add_argument(
        'password', metavar='PASS', help='password')
    parser.add_argument(
        'mount_point', metavar='MNTDIR', help='directory to mount filesystem at')

    args = parser.parse_args(argv[1:])

    username = args.__dict__.pop('username')
    password = args.__dict__.pop('password')
    mount_point = args.__dict__.pop('mount_point')

    # parse options
    options_str = args.__dict__.pop('options')
    options = dict([(kv.split('=', 1) + [True])[:2] for kv in (options_str and options_str.split(',')) or []])

    fuse_args = args.__dict__.copy()
    fuse_args.update(options)

    logfile = None
    if fuse_args.get('debug', False) == True:
        # send to stderr same as where fuse lib sends debug messages
        logfile = stderr

    if len(password) <= 0:
        password = getpass.getpass()
    FUSE(CopyFUSE(username, password, logfile=logfile), mount_point, **fuse_args)

if __name__ == "__main__":
    main()
