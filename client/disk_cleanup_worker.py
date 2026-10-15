"""Bounded allowlist cleanup through directory FDs. No shell, prune or truncation."""
import errno
import os
import re
import stat
import time

DAY = 86400
MAX_BYTES = 512 * 1024**2
MAX_FILES = 1000
ARCHIVE = re.compile(r'(?:syslog|messages|daemon\.log|kern\.log|debug|dmesg|boot\.log|access\.log|error\.log)(?:\.\d+|[-.]\d{8})(?:\.gz|\.xz|\.bz2|\.zst)?$')
JOURNAL = re.compile(r'(?:system|user-\d+)@[0-9a-f-]+\.journal(?:~)?$')
CADDY = re.compile(r'(?:(?:access|error)\.log(?:\.\d+|[-.]\d{8})|(?:access|error|caddy)-\d{4}-\d{2}-\d{2}T[\d.-]+\.log)(?:\.gz|\.xz|\.zst)?$')
RULES = (
    ('package_cache', 'var/cache/apt/archives', re.compile(r'.+\.deb$'), 1, 0),
    ('package_cache', 'var/cache/apk', re.compile(r'.+\.apk$'), 1, 0),
    ('package_cache', 'var/cache/pacman/pkg', re.compile(r'.+\.pkg\.tar\.(?:xz|zst)(?:\.sig)?$'), 1, 0),
    ('package_cache', 'var/cache/dnf', re.compile(r'.+\.rpm$'), 1, 3),
    ('package_cache', 'var/cache/yum', re.compile(r'.+\.rpm$'), 1, 3),
    ('archived_logs', 'var/log', ARCHIVE, 14, 0),
    ('archived_logs', 'var/log/nginx', ARCHIVE, 14, 0),
    ('archived_logs', 'var/log/apache2', ARCHIVE, 14, 0),
    ('archived_logs', 'var/log/caddy', CADDY, 14, 0),
    ('archived_logs', 'var/log/journal', JOURNAL, 14, 1),
    ('crash_files', 'var/crash', re.compile(r'.+\.(?:crash|upload|uploaded)$'), 14, 0),
    ('crash_files', 'var/lib/systemd/coredump', re.compile(r'core\..+\.(?:zst|lz4|xz)$'), 14, 0),
)


class UnsafeTarget(RuntimeError):
    pass


def mount_id(fd):
    with open('/proc/self/fdinfo/'+str(fd), encoding='ascii') as f:
        for line in f:
            if line.startswith('mnt_id:'):
                return int(line.split(':')[1])
    raise UnsafeTarget('mount identity unavailable')


def start_ticks(pid):
    with open('/proc/'+str(pid)+'/stat', encoding='ascii') as f:
        return f.read().rsplit(')', 1)[1].split()[19]


def disk(fd):
    s = os.fstatvfs(fd)
    used = (s.f_blocks-s.f_bfree)*s.f_frsize
    available = s.f_bavail*s.f_frsize
    return {'total_bytes':s.f_blocks*s.f_frsize, 'available_bytes':available,
            'used_percent':round(100*used/(used+available), 2) if used+available else 0}


def open_directory(root, relative, guest):
    """Each component is no-follow. Guest roots never cross a nested mount."""
    fd = os.dup(root)
    expected = mount_id(root) if guest else None
    try:
        for component in relative.split('/'):
            if not component or component in ('.','..'):
                raise UnsafeTarget('invalid allowlist path')
            child = os.open(component, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd);fd=child
            if guest and mount_id(fd)!=expected:
                raise UnsafeTarget('container bind or separate mount skipped')
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_files(deadline, limit=50000):
    """Failure to enumerate FDs is not proof that a file is unused."""
    busy=set();seen=0
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit():continue
        try:
            with os.scandir(entry.path+'/fd') as descriptors:
                for d in descriptors:
                    seen+=1
                    if seen>limit or time.monotonic()>deadline:
                        raise UnsafeTarget('open-file check budget exhausted')
                    try:
                        s=os.stat(d.path)
                        if stat.S_ISREG(s.st_mode):busy.add((s.st_dev,s.st_ino))
                    except (FileNotFoundError,ProcessLookupError):pass
        except (FileNotFoundError,ProcessLookupError):pass
        except PermissionError:raise UnsafeTarget('open-file permissions unavailable') from None
    return busy


def sweep(root_fd, execute=False, guest=False, retention_days=14, byte_budget=MAX_BYTES,
          file_budget=MAX_FILES, validate=None, busy=None, now=None, seconds=20):
    if not hasattr(os,'O_NOFOLLOW'):raise UnsafeTarget('Linux no-follow filesystem access required')
    if type(retention_days)!=int or not 14<=retention_days<=90:raise UnsafeTarget('invalid retention')
    if not 0<=byte_budget<=MAX_BYTES or not 0<=file_budget<=MAX_FILES:raise UnsafeTarget('invalid cleanup budget')
    now=time.time() if now is None else now
    deadline=time.monotonic()+seconds
    validate=validate or (lambda:None)
    validate();before=disk(root_fd)
    if busy is None:busy=open_files(deadline)
    result={'before':before,'after':before,'candidate_files':0,'candidate_bytes':0,
            'deleted_files':0,'unlinked_bytes':0,'freed_bytes':0,'skipped':0,'errors':0,
            'bounded':False,'categories':{},'status':'scanned' if not execute else 'succeeded'}
    visited=0
    def walk(directory, pattern, days, depth, category):
        nonlocal visited
        base_mount=mount_id(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                visited+=1
                if visited>20000 or time.monotonic()>deadline:
                    result['bounded']=True;return
                try:
                    s=entry.stat(follow_symlinks=False)
                    if depth and stat.S_ISDIR(s.st_mode):
                        if category=='archived_logs' and not re.fullmatch(r'[0-9a-f]{32}',entry.name):continue
                        sub=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                        try:
                            if mount_id(sub)==base_mount:walk(sub,pattern,days,depth-1,category)
                            else:result['skipped']+=1
                        finally:os.close(sub)
                        if result['bounded']:return
                        continue
                    if not pattern.fullmatch(entry.name) or not stat.S_ISREG(s.st_mode):continue
                    if s.st_nlink!=1 or max(s.st_mtime,s.st_ctime,s.st_atime)>now-days*DAY or (s.st_dev,s.st_ino) in busy:
                        result['skipped']+=1;continue
                    fd=os.open(entry.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
                    try:
                        verified=os.fstat(fd)
                        if mount_id(fd)!=base_mount or (verified.st_dev,verified.st_ino)!=(s.st_dev,s.st_ino):
                            result['skipped']+=1;continue
                        allocated=verified.st_blocks*512
                        result['candidate_files']+=1;result['candidate_bytes']+=allocated
                        totals=result['categories'].setdefault(category,{'candidate_bytes':0,'deleted_files':0})
                        totals['candidate_bytes']+=allocated
                        if execute:
                            if result['deleted_files']>=file_budget or result['unlinked_bytes']+allocated>byte_budget:
                                result['bounded']=True;continue
                            validate()
                            latest=os.stat(entry.name,dir_fd=directory,follow_symlinks=False)
                            if (latest.st_dev,latest.st_ino,latest.st_size,latest.st_mtime_ns,latest.st_ctime_ns)!=(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns):
                                result['skipped']+=1;continue
                            os.unlink(entry.name,dir_fd=directory)
                            result['deleted_files']+=1;result['unlinked_bytes']+=allocated;totals['deleted_files']+=1
                    finally:os.close(fd)
                except UnsafeTarget:raise
                except OSError as exc:
                    if exc.errno not in (errno.ENOENT,errno.ESRCH):result['errors']+=1
    for category,path,pattern,days,depth in RULES:
        try:
            directory=open_directory(root_fd,path,guest)
        except FileNotFoundError:continue
        except (OSError,UnsafeTarget):result['skipped']+=1;continue
        try:walk(directory,pattern,retention_days if days==14 else days,depth,category)
        except UnsafeTarget:
            result.update(status='partial',interrupted=True)
            break
        finally:os.close(directory)
        if visited>20000 or time.monotonic()>deadline:result['bounded']=True;break
    try:validate()
    except UnsafeTarget:result.update(status='partial',interrupted=True)
    result['after']=disk(root_fd)
    result['freed_bytes']=max(0,result['after']['available_bytes']-before['available_bytes'])
    if result['errors'] or result['bounded']:result['status']='partial'
    return result
