def FlagsForFile(filename, **kwargs):
    return {
            'flags': [ '-x', 'c', '-g', '-Wall', '-Werror'],
    }
