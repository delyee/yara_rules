from yara import compile
# rules = yara.compile('/foo/bar/my_rules’, externals= {'var1': 'some string’, 'var2': 4, 'var3': True})
compile(filepath='index.yar', includes=True).save('compiled_rules.yara')