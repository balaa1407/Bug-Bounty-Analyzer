from app.utils import calculate_jaccard_similarity


def test_jaccard_exact_match():
    t1 = "This is a SQL injection vulnerability in the login page."
    t2 = "This IS a sql injection VULNERABILITY in the login page."
    
    # Capitalization and spacing should be normalized out
    assert calculate_jaccard_similarity(t1, t2) == 1.0


def test_jaccard_empty_inputs():
    assert calculate_jaccard_similarity("", "") == 1.0
    assert calculate_jaccard_similarity("some text", "") == 0.0
    assert calculate_jaccard_similarity("", "other text") == 0.0


def test_jaccard_partial_matches():
    # 3 words overlap out of 5 unique words: {'a', 'b', 'c', 'd', 'e'}
    # Intersection: {'a', 'b', 'c'} -> size 3
    # Union: {'a', 'b', 'c', 'd', 'e'} -> size 5
    # Similarity: 3/5 = 0.6
    t1 = "a b c d"
    t2 = "a b c e"
    assert calculate_jaccard_similarity(t1, t2) == 0.6


def test_jaccard_disjoint_sets():
    t1 = "hello world"
    t2 = "cyber security audit"
    assert calculate_jaccard_similarity(t1, t2) == 0.0
