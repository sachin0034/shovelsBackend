import subprocess

from langchain.document_loaders import YoutubeLoader
from modules.mongodb import get_all_transcripts

from dotenv import find_dotenv, load_dotenv
import os
from openai import OpenAI
load_dotenv(find_dotenv())
api_key  = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def get_video_links(channel_url, max_links=5):
    command = [
        "yt-dlp",
        "--flat-playlist",
        "--yes-playlist",
        "--get-id",
        channel_url
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        video_ids = result.stdout.strip().split("\n")[:max_links]
        video_links = [f"https://www.youtube.com/watch?v={video_id}" for video_id in video_ids]
        print("Video links fetched successfully")
        return video_links
    except subprocess.CalledProcessError as e:
        print("Error occurred while fetching video links:", e)
        return []




# def make_transcript(urls):
    
#     # Directory to save audio files
#     save_dir = "./YouTube"

#     loader = GenericLoader(YoutubeAudioLoader(urls, save_dir), OpenAIWhisperParser())
#     docs = loader.load()
#     combined_docs = [doc.page_content for doc in docs]
#     text = " ".join(combined_docs)

#     return text


def make_transcript(urls):
    try:
        loader = YoutubeLoader.from_youtube_url(urls, add_video_info=True)
        docs = loader.load()
        combined_docs = [doc.page_content for doc in docs]
        text = " ".join(combined_docs)
        return text
    except Exception as e:
        print(f"Error making transcript: {e}")
        return False


def get_all_transcript(user_id,channel_id):
    """Get all transcripts of videos from the target youtube channel"""
    transcripts = get_all_transcripts(user_id,channel_id)
    return transcripts