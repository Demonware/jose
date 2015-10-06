import os
import sys

from setuptools import setup
from setuptools.command.bdist_rpm import bdist_rpm as _bdist_rpm

here = os.path.abspath(os.path.dirname(__file__))
REQUIRES = filter(lambda s: len(s) > 0,
        open(os.path.join(here, 'requirements.txt')).read().split('\n'))
pkg_name = 'jose'
pyver = ''.join(('python', '.'.join(map(str, sys.version_info[:2]))))

README = open(os.path.join(here, 'README')).read()
CHANGES = open(os.path.join(here, 'CHANGES')).read()
CONTRIB = open(os.path.join(here, 'CONTRIB')).read()


class bdist_rpm(_bdist_rpm):
    op_map = {
        '==': '=',
    }

    def finalize_package_data(self):
        self.requires = []
        for pkg, op, ver in map(lambda s: s.split(' '), REQUIRES):
            pkg = '-'.join((pyver.replace('.', ''), pkg))
            try:
                mop = self.op_map[op]
            except KeyError:
                mop = op

            self.requires.append(' {} '.format(mop).join((pkg, ver)))

        self.python = pyver
        if self.release is None:
            self.release = '.'.join((os.environ.get('JOSE_RELEASE', '1'),
                'demonware'))
        _bdist_rpm.finalize_package_data(self)


if __name__ == '__main__':
    if sys.argv[-1] == 'bdist_rpm':
        pkg_name = '-'.join((pyver.replace('.', ''), pkg_name))

    setup(name=pkg_name,
        version='1.0.0',
        author='Demian Brecht',
        author_email='dbrecht@demonware.net',
        py_modules=['jose'],
        url='https://github.com/Demonware/jose',
        description='An implementation of the JOSE draft',
        install_requires=REQUIRES,
        classifiers=[
            'Development Status :: 4 - Beta',
            'Intended Audience :: Developers',
            'Intended Audience :: Information Technology',
            'License :: OSI Approved :: BSD License',
            'Operating System :: OS Independent',
            'Programming Language :: Python :: 2 :: Only',
            'Topic :: Security',
            'Topic :: Software Development :: Libraries',],
        cmdclass={'bdist_rpm': bdist_rpm},
        entry_points = {
            'console_scripts': (
                'jose = jose:_cli',
            )
        },
        long_description='\n\n'.join((README, CHANGES, CONTRIB)),
    )
