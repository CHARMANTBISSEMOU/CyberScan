import os, shutil, win32file
src = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\History')
print('src exists:', os.path.exists(src))
dst1 = 'test1.db'
dst2 = 'test2.db'
dst3 = 'test3.db'

try:
    shutil.copy2(src, dst1)
    print('shutil ok')
except Exception as e:
    print('shutil error:', type(e).__name__, e)

try:
    with open(src, 'rb') as f1, open(dst2, 'wb') as f2:
        f2.write(f1.read())
    print('open ok')
except Exception as e:
    print('open error:', type(e).__name__, e)

try:
    win32file.CopyFile(src, dst3, False)
    print('win32file ok')
except Exception as e:
    print('win32file error:', type(e).__name__, e)
