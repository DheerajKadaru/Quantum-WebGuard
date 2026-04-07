from detector import URLDetector
import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORIZER_PATH = os.path.join(BASE_DIR, "artifacts", "tfidf_vectorizer.joblib")
MODEL_PATH = os.path.join(BASE_DIR, "artifacts", "best_model.joblib")

def test():
    detector = URLDetector(VECTORIZER_PATH, MODEL_PATH)
    
    test_urls = [
        "https://google1.com",           # Should trigger Rule-Based (1 in hostname)
        "https://youtube.com/watch?v=1", # Should be Trusted Domain (ignore path 1)
        "https://www.youtube.com",       # Should be Trusted Domain
        "http://paypa1-secure.net/login", # Should trigger Rule-Based (1 in hostname)
        "https://whatsapp.com",          # Should be Trusted Domain
        "https://alit.campx.in/",        # Should be Trusted Domain
        "https://random-new-site-xyz.org/path" # Likely Heuristic Fallback (Due to 0.92 threshold)
    ]
    
    print(f"{'URL':<40} | {'Pred':<15} | {'Source':<20} | {'Conf':<10}")
    print("-" * 95)
    
    for url in test_urls:
        try:
            res = detector.analyze(url)
            print(f"{url:<40} | {res['prediction']:<15} | {res['source']:<20} | {res['confidence']}%")
            print(f"  Reasoning: {res['reasoning']}\n")
        except Exception as e:
            print(f"Error analyzing {url}: {e}")

if __name__ == "__main__":
    test()
