import requests
from bs4 import BeautifulSoup
import py7zr
import os

url = "https://samples.vx-underground.org/samples/Families/CobaltStrike/"
directory = "./"
password = "infected"
response = requests.get(url)
html = response.text
soup = BeautifulSoup(html, "html.parser")


def download_file(url, save_path):
    response = requests.get(url)
    with open(save_path, "wb") as file:
        file.write(response.content)


def extract_7z(file_path, extract_path, password=None):
    with py7zr.SevenZipFile(file_path, mode="r", password=password) as z:
        z.extractall(extract_path)


# 7z 파일 링크 추출
file_urls = []
for link in soup.find_all("a"):
    href = link.get("href")
    if href and href.endswith(".7z"):
        file_urls.append(href)

# Download and unzip
for file_url in file_urls:
    file_name = file_url.split("/")[-1]
    save_file_path = os.path.join(directory, file_name)

    # download 7z
    download_file(file_url, save_file_path)

    # unzip 7z
    extract_7z(save_file_path, directory, password)

    # delete 7z
    os.remove(save_file_path)