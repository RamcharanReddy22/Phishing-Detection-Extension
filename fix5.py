with open('app.py', 'r') as f:
    content = f.read()

content = content.replace(
    'SAFE_BROWSING_API_KEY = "AIzaSyCwaHqxq84BzLaiZZCFd7U7rPkVSl9Ehcw"',
    'SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "AIzaSyCwaHqxq84BzLaiZZCFd7U7rPkVSl9Ehcw")'
)

with open('app.py', 'w') as f:
    f.write(content)

print("Done!")
