from analyses.tree_analyzer import TreeAnalyzer
from utility.test_util import build_tree, StateStub, build_identity_dict
from utility.tree import Tree
from IPython import embed

class TreeAnalyzerTests(object):

    @staticmethod
    def test_01():
        t = Tree()
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
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B4"})

        tanal = TreeAnalyzer(t, l)
        root_ist, res_post, res_pre = tanal.compute_block_histogram_per_edge()

        assert root_ist == {'B2': 1, 'B4': 1, 'B1': 1}
        assert res_post == {('B1', 'B2'): {'B2': 1}, ('B1', 'B4'): {'B4': 1}}
        assert res_pre  == {('B1', 'B2'): {'B1': 1}, ('B1', 'B4'): {'B1': 1}}
        
    @staticmethod
    def test_02():
        t = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": [
                        {
                            "id": 4,
                            "block": "B5",
                            "children": []
                        }
                    ]
                }, 
                {
                    "id": 3,
                    "block": "B4",
                    "children": []
                }
            ]
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B4", "B5"})

        tanal = TreeAnalyzer(t, l)
        root_ist, res_post, res_pre = tanal.compute_block_histogram_per_edge()

        assert root_ist == {'B5': 1, 'B2': 1, 'B4': 1, 'B1': 1}
        assert res_post == {('B2', 'B5'): {'B5': 1}, ('B1', 'B2'): {'B5': 1, 'B2': 1}, ('B1', 'B4'): {'B4': 1}}
        assert res_pre  == {('B2', 'B5'): {'B1': 1, 'B2': 1}, ('B1', 'B2'): {'B1': 1}, ('B1', 'B4'): {'B1': 1}}

    @staticmethod
    def test_03():
        t = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": [
                        {
                            "id": 4,
                            "block": "B5",
                            "children": []
                        },
                        {
                            "id": 6,
                            "block": "B3",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B1",
                                    "children": []
                                },
                                {
                                    "id": 8,
                                    "block": "B1",
                                    "children": []
                                }
                            ]
                        }
                    ]
                }, 
                {
                    "id": 3,
                    "block": "B4",
                    "children": []
                }
            ]
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B3", "B4", "B5"})

        tanal = TreeAnalyzer(t, l)
        root_ist, res_post, res_pre = tanal.compute_block_histogram_per_edge()

        assert root_ist == {'B5': 1, 'B1': 3, 'B3': 1, 'B2': 1, 'B4': 1}
        assert res_post == {('B2', 'B5'): {'B5': 1}, ('B3', 'B1'): {'B1': 2}, ('B2', 'B3'): {'B1': 2, 'B3': 1},
                       ('B1', 'B2'): {'B5': 1, 'B1': 2, 'B3': 1, 'B2': 1}, ('B1', 'B4'): {'B4': 1}}
        assert res_pre  == {('B2', 'B5'): {'B1': 1, 'B2': 1},
                            ('B3', 'B1'): {'B1': 1, 'B2': 1, 'B3': 1},
                            ('B2', 'B3'): {'B1': 1, 'B2': 1},
                            ('B1', 'B2'): {'B1': 1},
                            ('B1', 'B4'): {'B1': 1}}

    @staticmethod
    def test_04():
        t = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": [
                        {
                            "id": 4,
                            "block": "B5",
                            "children": []
                        },
                        {
                            "id": 6,
                            "block": "B3",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B1",
                                    "children": []
                                },
                                {
                                    "id": 8,
                                    "block": "B1",
                                    "children": []
                                }
                            ]
                        }
                    ]
                }, 
                {
                    "id": 3,
                    "block": "B4",
                    "children": []
                }
            ]
        }, t, 0)
        l = build_identity_dict({"B2", "B3", "B4", "B5"})

        tanal = TreeAnalyzer(t, l)
        root_ist, res_post, res_pre = tanal.compute_block_histogram_per_edge()

        assert root_ist == {'B5': 1, 'B3': 1}
        assert res_post == {('B2', 'B5'): {'B5': 1}, ('B2', 'B3'): {'B3': 1}}
        assert res_pre  == {('B2', 'B5'): {'B2': 1}, ('B2', 'B3'): {'B2': 1}}

    @staticmethod
    def test_05():
        t = Tree()
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
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B3", "B4", "B5", "B6", "B7"})

        tanal = TreeAnalyzer(t, l)
        root_ist, res_post, res_pre = tanal.compute_block_histogram_per_edge()


        assert root_ist == {'B1': 2, 'B2': 1, 'B3': 2, 'B4': 1, 'B5': 1, 'B6': 1, 'B7': 1}
        assert res_post == {
            ('B7', 'B5'): {'B5': 1, 'B4': 1, 'B3': 2, 'B1': 2, 'B6': 1, 'B2': 1},
            ('B5', 'B4'): {'B4': 1, 'B3': 1, 'B1': 1}, 
            ('B4', 'B3'): {'B3': 1, 'B1': 1},
            ('B3', 'B1'): {'B1': 2, 'B6': 1},  # merged edge
            ('B5', 'B3'): {'B3': 1, 'B1': 1, 'B6': 1, 'B2': 1},
            ('B3', 'B2'): {'B2': 1},
            ('B1', 'B6'): {'B6': 1}
        }
        assert res_pre == {
            ('B3', 'B2'): {'B7': 1, 'B3': 1, 'B5': 1},
            ('B1', 'B6'): {'B7': 1, 'B3': 1, 'B1': 1, 'B5': 1},
            ('B3', 'B1'): {'B5': 1, 'B3': 2, 'B4': 1, 'B7': 1},
            ('B5', 'B3'): {'B7': 1, 'B5': 1},
            ('B4', 'B3'): {'B7': 1, 'B4': 1, 'B5': 1},
            ('B5', 'B4'): {'B7': 1, 'B5': 1},
            ('B7', 'B5'): {'B7': 1}
        }

    @staticmethod
    def test_06():
        t = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": [
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
                }
            ]
        }, t, 0)

        l = build_identity_dict({"B1", "B2"})

        tanal = TreeAnalyzer(t, l)
        root_ist, res_post, res_pre = tanal.compute_block_histogram_per_edge()

        assert res_post == {('B2', 'B1'): {'B2': 1, 'B1': 1}, ('B1', 'B2'): {'B2': 2, 'B1': 1}}
        assert res_pre  == {('B2', 'B1'): {'B1': 1, 'B2': 1}, ('B1', 'B2'): {'B1': 1}}
        assert root_ist == {'B2': 2, 'B1': 2}

    @staticmethod
    def test_07():
        t = Tree()
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
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B3", "B4", "B5", "B6", "B7"})

        tanal = TreeAnalyzer(t, l)
        total_nodes, res_post, res_pre = tanal.compute_node_count_per_edge()

        assert res_post == {
            ('B3', 'B2'): 1,
            ('B1', 'B6'): 1,
            ('B3', 'B1'): 3,
            ('B5', 'B3'): 4,
            ('B4', 'B3'): 2,
            ('B5', 'B4'): 3,
            ('B7', 'B5'): 8
        }
        assert res_pre == {
            ('B3', 'B2'): 3,
            ('B1', 'B6'): 4,
            ('B3', 'B1'): 5,
            ('B5', 'B3'): 2,
            ('B4', 'B3'): 3,
            ('B5', 'B4'): 2,
            ('B7', 'B5'): 1
        }
        assert total_nodes == 9

    @staticmethod
    def test_08():
        t = Tree()
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
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B3", "B4", "B5", "B6", "B7"})

        tanal     = TreeAnalyzer(t, l)
        edges_black  = tanal.compute_coverage_loss_per_edge_black()
        edges_white  = tanal.compute_coverage_loss_per_edge_white()
        blocks_black = tanal.compute_coverage_loss_per_block_black()
        blocks_white = tanal.compute_coverage_loss_per_block_white()

        assert edges_black == [
            {'src': 'B3', 'dst': 'B2', 'coverage_loss': 14.29, 'tree_reduction': 11.11}, 
            {'src': 'B1', 'dst': 'B6', 'coverage_loss': 14.29, 'tree_reduction': 11.11}, 
            {'src': 'B3', 'dst': 'B1', 'coverage_loss': 28.57, 'tree_reduction': 33.33}, 
            {'src': 'B5', 'dst': 'B3', 'coverage_loss': 28.57, 'tree_reduction': 44.44}, 
            {'src': 'B4', 'dst': 'B3', 'coverage_loss':  0.0 , 'tree_reduction': 22.22}, 
            {'src': 'B5', 'dst': 'B4', 'coverage_loss': 14.29, 'tree_reduction': 33.33}, 
            {'src': 'B7', 'dst': 'B5', 'coverage_loss': 85.71, 'tree_reduction': 88.89}
        ]
        assert edges_white == [
            {'src': 'B3', 'dst': 'B2', 'coverage_loss': 42.86, 'tree_reduction': 55.56},
            {'src': 'B1', 'dst': 'B6', 'coverage_loss': 28.57, 'tree_reduction': 44.44},
            {'src': 'B3', 'dst': 'B1', 'coverage_loss': 14.29, 'tree_reduction': 11.11},
            {'src': 'B5', 'dst': 'B3', 'coverage_loss': 14.29, 'tree_reduction': 33.33},
            {'src': 'B4', 'dst': 'B3', 'coverage_loss': 28.57, 'tree_reduction': 44.44},
            {'src': 'B5', 'dst': 'B4', 'coverage_loss': 28.57, 'tree_reduction': 44.44},
            {'src': 'B7', 'dst': 'B5', 'coverage_loss': 0.0,   'tree_reduction': 0.0}
        ]
        assert blocks_black == [
            {'block_id': 'B2', 'coverage_loss': 14.29, 'tree_reduction': 11.11},
            {'block_id': 'B6', 'coverage_loss': 14.29, 'tree_reduction': 11.11},
            {'block_id': 'B1', 'coverage_loss': 28.57, 'tree_reduction': 33.33},
            {'block_id': 'B3', 'coverage_loss': 57.14, 'tree_reduction': 66.67},
            {'block_id': 'B4', 'coverage_loss': 14.29, 'tree_reduction': 33.33},
            {'block_id': 'B5', 'coverage_loss': 85.71, 'tree_reduction': 88.89},
            {'block_id': 'B7', 'coverage_loss': 100.0, 'tree_reduction': 100.0}
        ]
        assert blocks_white == [
            {'block_id': 'B2', 'coverage_loss': 42.86, 'tree_reduction': 55.56},
            {'block_id': 'B6', 'coverage_loss': 28.57, 'tree_reduction': 44.44},
            {'block_id': 'B1', 'coverage_loss': 14.29, 'tree_reduction': 11.11},
            {'block_id': 'B3', 'coverage_loss': 0.0,   'tree_reduction': 0.0},
            {'block_id': 'B4', 'coverage_loss': 28.57, 'tree_reduction': 44.44},
            {'block_id': 'B5', 'coverage_loss': 0.0,   'tree_reduction': 0.0},
            {'block_id': 'B7', 'coverage_loss': 0.0,   'tree_reduction': 0.0}
        ]

    @staticmethod
    def test_09():
        t = Tree()
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
                                            "block": "B2",
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
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B3", "B4", "B5", "B6", "B7"})

        tanal = TreeAnalyzer(t, l)
        root_ist, res_post, res_pre = tanal.compute_block_histogram_per_edge(dropped_edges=set([("B5", "B4")]))

        assert res_post == {
            ('B3', 'B2'): {'B2': 1},
            ('B1', 'B2'): {'B2': 1},
            ('B3', 'B1'): {'B2': 1, 'B1': 1},
            ('B5', 'B3'): {'B2': 2, 'B1': 1, 'B3': 1},
            ('B7', 'B5'): {'B2': 2, 'B1': 1, 'B3': 1, 'B5': 1}
        }

        assert res_pre == {
            ('B3', 'B2'): {'B7': 1, 'B3': 1, 'B5': 1},
            ('B1', 'B2'): {'B7': 1, 'B3': 1, 'B1': 1, 'B5': 1},
            ('B3', 'B1'): {'B7': 1, 'B3': 1, 'B5': 1},
            ('B5', 'B3'): {'B7': 1, 'B5': 1},
            ('B7', 'B5'): {'B7': 1}
        }
        assert root_ist == {'B2': 2, 'B1': 1, 'B3': 1, 'B5': 1, 'B7': 1}

    @staticmethod
    def test_10():
        t = Tree()
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
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B3", "B4", "B5", "B6", "B7"})

        tanal = TreeAnalyzer(t, l)
        root_ist, res_post, res_pre = tanal.compute_block_histogram_per_block()

        assert root_ist == {'B2': 1, 'B6': 1, 'B1': 2, 'B3': 2, 'B4': 1, 'B5': 1, 'B7': 1}
        assert res_post == {
            'B2': {'B2': 1},
            'B6': {'B6': 1},
            'B1': {'B1': 2, 'B6': 1},
            'B3': {'B3': 2, 'B2': 1, 'B6': 1, 'B1': 2},
            'B4': {'B4': 1, 'B1': 1, 'B3': 1},
            'B5': {'B5': 1, 'B2': 1, 'B6': 1, 'B1': 2, 'B3': 2, 'B4': 1},
            'B7': {'B7': 1, 'B2': 1, 'B6': 1, 'B1': 2, 'B3': 2, 'B4': 1, 'B5': 1}
        }
        assert res_pre == {
            'B2': {'B7': 1, 'B3': 1, 'B5': 1},
            'B6': {'B7': 1, 'B3': 1, 'B1': 1, 'B5': 1},
            'B1': {'B5': 1, 'B3': 2, 'B4': 1, 'B7': 1},
            'B3': {'B5': 1, 'B4': 1, 'B7': 1},
            'B4': {'B7': 1, 'B5': 1},
            'B5': {'B7': 1},
            'B7': {}
        }

    @staticmethod
    def test_11():
        t = Tree()
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
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B3", "B4", "B5", "B6", "B7"})

        tanal = TreeAnalyzer(t, l)
        total_nodes, res_post, res_pre = tanal.compute_node_count_per_block()

        assert total_nodes == 9
        assert res_post == {'B2': 1, 'B6': 1, 'B1': 3, 'B3': 6, 'B4': 3, 'B5': 8, 'B7': 9}
        assert res_pre  == {'B2': 3, 'B6': 4, 'B1': 5, 'B3': 3, 'B4': 2, 'B5': 1, 'B7': 0}

    @staticmethod
    def test_12():
        t = Tree()
        build_tree({
            "id": 1,
            "block": "B1",
            "children": [
                {
                    "id": 2,
                    "block": "B2",
                    "children": [
                        {
                            "id": 4,
                            "block": "B5",
                            "children": []
                        },
                        {
                            "id": 6,
                            "block": "B3",
                            "children": [
                                {
                                    "id": 7,
                                    "block": "B1",
                                    "children": []
                                },
                                {
                                    "id": 8,
                                    "block": "B1",
                                    "children": []
                                }
                            ]
                        }
                    ]
                }, 
                {
                    "id": 3,
                    "block": "B4",
                    "children": []
                }
            ]
        }, t, 0)
        l = build_identity_dict({"B1", "B2", "B3", "B4", "B5"})

        tanal = TreeAnalyzer(t, l)
        root_hist, res_post, res_pre = tanal.compute_block_histogram_per_block()

        assert root_hist == {'B5': 1, 'B1': 3, 'B3': 1, 'B2': 1, 'B4': 1}
        assert res_post == {
            'B5': {'B5': 1},
            'B3': {'B1': 2, 'B3': 1},
            'B2': {'B5': 1, 'B1': 2, 'B3': 1, 'B2': 1},
            'B4': {'B4': 1},
            'B1': {'B5': 1, 'B1': 3, 'B3': 1, 'B2': 1, 'B4': 1}
        }

        assert res_pre  == {
            'B5': {'B1': 1, 'B2': 1},
            'B3': {'B1': 1, 'B2': 1},
            'B2': {'B1': 1},
            'B4': {'B1': 1},
            'B1': {}
        }
