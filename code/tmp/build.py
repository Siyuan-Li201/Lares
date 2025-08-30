from tree_sitter import Language
import os


os.chdir("./tmp/")


Language.build_library(

  # Store the library in the `build` directory
  'build/my-languages.so',

  # Include one or more languages
  [
    'vendor/tree-sitter-c',
    'vendor/tree-sitter-cpp'
    # 'vendor/tree-sitter-java',
    # 'vendor/tree-sitter-python',
    # 'vendor/tree-sitter-cpp',
  ]
)
