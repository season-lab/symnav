from analyses.tree_pruner import TreePruner
from utility.test_util import build_tree, StateStub, build_identity_dict
from utility.tree import Tree
from angr_wrapper import Symbol
from IPython import embed
import claripy

class TreePrunerTests(object):

    t1 = Tree()
    l1 = dict()

    t2 = Tree()
    l2 = dict()

    t3 = Tree()
    l3 = dict()

    t4 = Tree()
    l4 = dict()
    s4 = dict()

    t5 = Tree()
    l5 = dict()
    s5 = dict()

    t6 = Tree()
    l6 = dict()

    def __init__(self):
        
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": []
                }, 
                {
                    "id": 3,
                    "block": "B4",
                    "children": []
                }
            ]
        }, TreePrunerTests.t1, 0)
        TreePrunerTests.l1 = build_identity_dict({"B1", "B2", "B4"})

        build_tree({
            "id": 9,
            "block": "B7",
            "children": [
                {
                    "id": 1,
                    "block": "B5",
                    "children": [
                        {
                            "id": 2,
                            "block": "B3",
                            "children": [
                                {
                                    "id": 4,
                                    "block": "B2",
                                    "children": []
                                },
                                {
                                    "id": 5,
                                    "block": "B1",
                                    "children": [
                                        {
                                            "id": 6,
                                            "block": "B6",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }, 
                        {
                            "id": 3,
                            "block": "B4",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B3",
                                    "children": [
                                        {
                                            "id": 8,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                },
                                {
                                    "id": 11,
                                    "block": "B8",
                                    "children": []
                                }
                            ]
                        }
                    ]
                },
                {
                    "id": 10,
                    "block": "B9",
                    "children": []
                }
            ]
        }, TreePrunerTests.t2, 0)
        TreePrunerTests.l2 = build_identity_dict({"B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9"})

        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": []
                }, 
                {
                    "id": 3,
                    "block": "B1",
                    "children": [
                        {
                            "id": 4,
                            "block": "B2",
                            "children": []
                        },
                        {
                            "id": 5,
                            "block": "B1",
                            "children": [
                                {
                                    "id": 6,
                                    "block": "B2",
                                    "children": []
                                },
                                {
                                    "id": 7,
                                    "block": "B1",
                                    "children": [
                                        {
                                            "id": 8,
                                            "block": "B2",
                                            "children": []
                                        },
                                        {
                                            "id": 9,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }, TreePrunerTests.t3, 0)
        TreePrunerTests.l3 = build_identity_dict({"B1", "B2"})

        s1 = claripy.BVS('s1', 32)
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": [],
                    "constraints": [
                        claripy.SGT(s1, 0)
                    ]
                }, 
                {
                    "id": 3,
                    "block": "B4",
                    "children": [],
                    "constraints": [
                        claripy.SLE(s1, 0)
                    ]
                }
            ]
        }, TreePrunerTests.t4, 0)
        TreePrunerTests.l4 = build_identity_dict({"B1", "B2", "B4"})
        TreePrunerTests.s4 = {
            's1': Symbol('s1', '', s1, 1, "", "UNKNOWN")
        }

        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B3",
                    "constraints": [
                        claripy.SLE(s1, 10)
                    ],
                    "children": []
                },
                {
                    "id": 3,
                    "block": "B2",
                    "constraints": [
                        claripy.SGT(s1, 10)
                    ],
                    "children": [
                        {
                            "id": 4,
                            "block": "B4",
                            "constraints": [
                                claripy.SGT(s1, 10),
                                claripy.SLE(s1, 20)
                            ],
                            "children": []
                        },
                        {
                            "id": 5,
                            "block": "B5",
                            "constraints": [
                                claripy.SGT(s1, 20)
                            ],
                            "children": []
                        }
                    ]
                }
            ]
        }, TreePrunerTests.t5, 0)
        TreePrunerTests.l5 = build_identity_dict({"B1", "B2", "B3", "B4", "B5"})
        TreePrunerTests.s5 = {
            's1': Symbol('s1', '', s1, 1, "", "UNKNOWN")
        }

        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": []
                },
                {
                    "id": 3,
                    "block": "B1",
                    "children": [
                        {
                            "id": 4,
                            "block": "B2",
                            "children": []
                        },
                        {
                            "id": 5,
                            "block": "B1",
                            "children": [
                                {
                                    "id": 6,
                                    "block": "B2",
                                    "children": []
                                },
                                {
                                    "id": 7,
                                    "block": "B1",
                                    "children": [
                                        {
                                            "id": 8,
                                            "block": "B2",
                                            "children": []
                                        },
                                        {
                                            "id": 9,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }, TreePrunerTests.t6, 0)
        TreePrunerTests.l6 = build_identity_dict({"B1", "B2"})

    @staticmethod
    def test_01():
        
        tpru = TreePruner(TreePrunerTests.t1, TreePrunerTests.l1, dict())
        new_tree = tpru.filter_tree([{
            "type":     "filter_block",
            "block_id": "B4",
            "mode":     "black"
        }])

        res = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": []
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_02():
        
        tpru = TreePruner(TreePrunerTests.t2, TreePrunerTests.l2, dict())
        new_tree = tpru.filter_tree([{
            "type":     "filter_block",
            "block_id": "B5",
            "mode":     "black"
        },
        {
            "type":     "filter_block",
            "block_id": "B9",
            "mode":     "black"
        }])

        res = Tree()  # not it drops all the nodes
        # build_tree({
        #     "id": 9,
        #     "block": "B7",
        #     "children": []
        # }, res, 0)
        
        assert new_tree == res
    
    @staticmethod
    def test_03():
        
        tpru = TreePruner(TreePrunerTests.t2, TreePrunerTests.l2, dict())
        new_tree = tpru.filter_tree([{
            "type":     "filter_block",
            "block_id": "B3",
            "mode":     "black"
        }])

        res = Tree()
        build_tree({
            "id": 9,
            "block": "B7",
            "children": [
                {
                    "id": 1,
                    "block": "B5",
                    "children": [
                        {
                            "id": 3,
                            "block": "B4",
                            "children": [
                                {
                                    "id": 11,
                                    "block": "B8",
                                    "children": []
                                }
                            ]
                        }
                    ]
                },
                {
                    "id": 10,
                    "block": "B9",
                    "children": []
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_04():
        
        tpru = TreePruner(TreePrunerTests.t2, TreePrunerTests.l2, dict())
        new_tree = tpru.filter_tree([{
            "type":   "filter_edge",
            "src_id": "B5",
            "dst_id": "B3",
            "mode":   "black"
        }])

        res = Tree()
        build_tree({
            "id": 9,
            "block": "B7",
            "children": [
                {
                    "id": 1,
                    "block": "B5",
                    "children": [
                        {
                            "id": 3,
                            "block": "B4",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B3",
                                    "children": [
                                        {
                                            "id": 8,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                },
                                {
                                    "id": 11,
                                    "block": "B8",
                                    "children": []
                                }
                            ]
                        }
                    ]
                },
                {
                    "id": 10,
                    "block": "B9",
                    "children": []
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_05():
        
        tpru = TreePruner(TreePrunerTests.t2, TreePrunerTests.l2, dict())
        new_tree = tpru.filter_tree([{
            "type":   "filter_edge",
            "src_id": "B3",
            "dst_id": "B2",
            "mode":   "black"
        },
        {
            "type":     "filter_block",
            "block_id": "B9",
            "mode":     "black"
        },
        {
            "type":     "filter_block",
            "block_id": "B8",
            "mode":     "black"
        }])

        res = Tree()
        build_tree({
            "id": 9,
            "block": "B7",
            "children": [
                {
                    "id": 1,
                    "block": "B5",
                    "children": [
                        {
                            "id": 2,
                            "block": "B3",
                            "children": [
                                {
                                    "id": 5,
                                    "block": "B1",
                                    "children": [
                                        {
                                            "id": 6,
                                            "block": "B6",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }, 
                        {
                            "id": 3,
                            "block": "B4",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B3",
                                    "children": [
                                        {
                                            "id": 8,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_06():
        
        tpru = TreePruner(TreePrunerTests.t2, TreePrunerTests.l2, dict())
        new_tree = tpru.filter_tree([{
            "type":     "filter_block",
            "block_id": "B4",
            "mode":     "white"
        }])

        res = Tree()
        build_tree({
            "id": 9,
            "block": "B7",
            "children": [
                {
                    "id": 1,
                    "block": "B5",
                    "children": [
                        {
                            "id": 3,
                            "block": "B4",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B3",
                                    "children": [
                                        {
                                            "id": 8,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                },
                                {
                                    "id": 11,
                                    "block": "B8",
                                    "children": []
                                }
                            ]
                        }
                    ]
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_07():
        
        tpru = TreePruner(TreePrunerTests.t2, TreePrunerTests.l2, dict())
        new_tree = tpru.filter_tree([{
            "type":     "filter_block",
            "block_id": "B4",
            "mode":     "white"
        },
        {
            "type":     "filter_block",
            "block_id": "B8",
            "mode":     "white"
        }])

        res = Tree()
        build_tree({
            "id": 9,
            "block": "B7",
            "children": [
                {
                    "id": 1,
                    "block": "B5",
                    "children": [
                        {
                            "id": 3,
                            "block": "B4",
                            "children": [
                                {
                                    "id": 11,
                                    "block": "B8",
                                    "children": []
                                }
                            ]
                        }
                    ]
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_08():
        
        tpru = TreePruner(TreePrunerTests.t2, TreePrunerTests.l2, dict())
        new_tree = tpru.filter_tree([{
            "type":     "filter_block",
            "block_id": "B3",
            "mode":     "white"
        }])

        res = Tree()
        build_tree({
            "id": 9,
            "block": "B7",
            "children": [
                {
                    "id": 1,
                    "block": "B5",
                    "children": [
                        {
                            "id": 2,
                            "block": "B3",
                            "children": [
                                {
                                    "id": 4,
                                    "block": "B2",
                                    "children": []
                                },
                                {
                                    "id": 5,
                                    "block": "B1",
                                    "children": [
                                        {
                                            "id": 6,
                                            "block": "B6",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }, 
                        {
                            "id": 3,
                            "block": "B4",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B3",
                                    "children": [
                                        {
                                            "id": 8,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_09():
        
        tpru = TreePruner(TreePrunerTests.t2, TreePrunerTests.l2, dict())
        new_tree = tpru.filter_tree([{
            "type":   "filter_edge",
            "src_id": "B3",
            "dst_id": "B2",
            "mode":   "white"
        }])

        res = Tree()
        build_tree({
            "id": 9,
            "block": "B7",
            "children": [
                {
                    "id": 1,
                    "block": "B5",
                    "children": [
                        {
                            "id": 2,
                            "block": "B3",
                            "children": [
                                {
                                    "id": 4,
                                    "block": "B2",
                                    "children": []
                                }
                            ]
                        }
                    ]
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_10():
        
        tpru = TreePruner(TreePrunerTests.t2, TreePrunerTests.l2, dict())
        new_tree = tpru.filter_tree([{
            "type":   "filter_edge",
            "src_id": "B3",
            "dst_id": "B1",
            "mode":   "white"
        },
        {
            "type":     "filter_block",
            "block_id": "B4",
            "mode":     "white"
        }])

        res = Tree()
        build_tree({
            "id": 9,
            "block": "B7",
            "children": [
                {
                    "id": 1,
                    "block": "B5",
                    "children": [
                        {
                            "id": 3,
                            "block": "B4",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B3",
                                    "children": [
                                        {
                                            "id": 8,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_11():
        
        tpru = TreePruner(TreePrunerTests.t3, TreePrunerTests.l3, dict())
        new_tree = tpru.filter_tree([{
            "type":     "limit_fork",
            "block_id": "B1",
            "num_fork": "2"
        }])

        res = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": []
                }, 
                {
                    "id": 3,
                    "block": "B1",
                    "children": [
                        {
                            "id": 4,
                            "block": "B2",
                            "children": []
                        },
                        {
                            "id": 5,
                            "block": "B1",
                            "children": [
                                {
                                    "id": 6,
                                    "block": "B2",
                                    "children": []
                                }
                            ]
                        }
                    ]
                }
            ]
        }, res, 0)
        
        assert new_tree == res

    @staticmethod
    def test_12():

        tpru = TreePruner(TreePrunerTests.t4, TreePrunerTests.l4, TreePrunerTests.s4)
        new_tree = tpru.filter_tree([{
            "type":      "limit_symbol",
            "symbol_id": "s1",
            "min":       "1",
            "max":       str(2**31-1)
        }])

        res = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": []
                }
            ]
        }, res, 0)

        assert new_tree == res

    @staticmethod
    def test_13():

        tpru = TreePruner(TreePrunerTests.t4, TreePrunerTests.l4, TreePrunerTests.s4)
        new_tree = tpru.filter_tree([{
            "type":      "limit_symbol",
            "symbol_id": "s1",
            "min":       str(-2**31),
            "max":       "0"
        }])

        res = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 3,
                    "block": "B4",
                    "children": []
                }
            ]
        }, res, 0)

        assert new_tree == res

    @staticmethod
    def test_14():

        tpru = TreePruner(TreePrunerTests.t5, TreePrunerTests.l5, TreePrunerTests.s5)
        new_tree = tpru.filter_tree([{
            "type":      "limit_symbol",
            "symbol_id": "s1",
            "min":       "11",
            "max":       "15"
        }])

        res = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 3,
                    "block": "B2",
                    "children": [
                        {
                            "id": 4,
                            "block": "B4",
                            "children": []
                        }
                    ]
                }
            ]
        }, res, 0)

        assert new_tree == res

    @staticmethod
    def test_15():

        tpru = TreePruner(TreePrunerTests.t6, TreePrunerTests.l6, dict())
        new_tree = tpru.filter_tree([{
            "type":     "filter_block",
            "block_id": "B1",
            "mode":     "black",
            "count":    "2"
        }])

        res = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": []
                },
                {
                    "id": 3,
                    "block": "B1",
                    "children": [
                        {
                            "id": 4,
                            "block": "B2",
                            "children": []
                        }
                    ]
                }
            ]
        }, res, 0)

        assert new_tree == res

    @staticmethod
    def test_16():

        tpru = TreePruner(TreePrunerTests.t6, TreePrunerTests.l6, dict())
        new_tree = tpru.filter_tree([{
            "type":     "filter_edge",
            "src_id":   "B1",
            "dst_id":   "B1",
            "mode":     "black",
            "count":    "1"
        }])

        res = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": []
                },
                {
                    "id": 3,
                    "block": "B1",
                    "children": [
                        {
                            "id": 4,
                            "block": "B2",
                            "children": []
                        }
                    ]
                }
            ]
        }, res, 0)

        assert new_tree == res

    @staticmethod
    def test_17():
        
        tpru = TreePruner(TreePrunerTests.t3, TreePrunerTests.l3, dict())
        new_tree = tpru.filter_tree([{
            "type":        "limit_fork",
            "block_id":    "B1",
            "num_fork":    "0",
            "fork_choice": "B1"
        }])

        res = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 3,
                    "block": "B1",
                    "children": [
                        {
                            "id": 5,
                            "block": "B1",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B1",
                                    "children": [
                                        {
                                            "id": 9,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }, res, 0)        
        assert new_tree == res

    @staticmethod
    def test_18():
        tpru = TreePruner(TreePrunerTests.t3, TreePrunerTests.l3, dict())
        new_tree = tpru.filter_tree([{
            "type":        "limit_fork",
            "block_id":    "B1",
            "num_fork":    "1",
            "fork_choice": "B1"
        }])

        res = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": []
                },
                {
                    "id": 3,
                    "block": "B1",
                    "children": [
                        {
                            "id": 5,
                            "block": "B1",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B1",
                                    "children": [
                                        {
                                            "id": 9,
                                            "block": "B1",
                                            "children": []
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }, res, 0)
        assert new_tree == res
