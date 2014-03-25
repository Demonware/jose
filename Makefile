.PHONY: test docs lint clean bdist bdist_rpm ln

lint:
	flake8 jose.py 

docs:
	pushd ./docs; \
	make html; \
	popd

test:
	rm -f .coverage
	nosetests -s --with-coverage --cover-package=jose --cov=./src

clean:
	rm -rf build dist *.egg-info
	find . -name "*.pyc" | xargs rm -f

bdist: clean
	python2.7 setup.py bdist

bdist_rpm: clean
	python2.7 setup.py bdist_rpm
