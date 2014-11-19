import os
import sys

from setuptools import setup
from setuptools.command.bdist_rpm import bdist_rpm as _bdist_rpm

here = os.path.abspath(os.path.dirname(__file__))
REQUIRES = filter(lambda s: len(s) > 0,
        open(os.path.join(here, 'requirements.txt')).read().split('\n'))
pkg_name = 'jose'
pyver = ''.join(('python', '.'.join(map(str, sys.version_info[:2]))))


class bdist_rpm(_bdist_rpm):
    def finalize_package_data(self):
        self.requires = []
        for pkg, ver in map(lambda s: s.split('=='), REQUIRES):
            pkg = '-'.join((pyver.replace('.', ''), pkg))
            self.requires.append(' = '.join((pkg, ver)))
        
        self.python = pyver
        if self.release is None:
            self.release = '.'.join((os.environ.get('JOSE_RELEASE', '1'),
                'demonware'))
        _bdist_rpm.finalize_package_data(self)


if __name__ == '__main__':
    if sys.argv[-1] == 'bdist_rpm':
        pkg_name = '-'.join((pyver.replace('.', ''), pkg_name))

    setup(name=pkg_name,
        version='0.1.1',
        author='Demian Brecht',
        author_email='dbrecht@demonware.net',
        py_modules=['jose'],
        url='https://github.com/Demonware/jose',
        description='An implementation of the JOSE draft',
        install_requires=REQUIRES,
        classifiers=[],
        cmdclass={'bdist_rpm': bdist_rpm},
    )
