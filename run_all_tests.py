from unit_tests.tree_analyzer_tests import TreeAnalyzerTests
from unit_tests.tree_pruner_tests import TreePrunerTests
from utility.test_util import do_test

if __name__ == "__main__":
    print()
    print("**** TREE ANALYZER ****")
    t_obj = TreeAnalyzerTests()
    tests = [getattr(t_obj, el) for el in dir(t_obj) if "test_" in el]
    for t in tests:
        do_test(t)
    print()
    print("**** TREE PRUNER ****")
    t_obj = TreePrunerTests()
    tests = [getattr(t_obj, el) for el in dir(t_obj) if "test_" in el]
    for t in tests:
        do_test(t)
    print()
