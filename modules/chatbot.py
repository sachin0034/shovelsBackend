from openai import OpenAI
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores.faiss import FAISS
from langchain.agents import OpenAIFunctionsAgent, AgentExecutor
from langchain.agents.openai_functions_agent.agent_token_buffer_memory import (AgentTokenBufferMemory, )
from langchain.chat_models import ChatOpenAI
from langchain.schema import SystemMessage, AIMessage, HumanMessage
from langchain.prompts import MessagesPlaceholder
from langchain.agents import AgentExecutor
from langchain.tools import StructuredTool
from langchain.llms import OpenAI
from modules.ai_tools import get_all_transcript
from langchain.llms import OpenAI
from modules.mongodb import get_history,set_history,update_session

import os
from dotenv import find_dotenv, load_dotenv
load_dotenv(find_dotenv())
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(
    # This is the default and can be omitted
    api_key=OPENAI_API_KEY,
)


def get_transcripts(user_id:str, channel_id:str) -> str:
    """Get all transcripts of videos from the target youtube channel"""
    
    if channel_id=='000000' or channel_id=='-101':
        return "No transcripts found for this channel, please continue with the conversation."
    if not user_id:
        return "Please provide your user_id"
    if not channel_id:
        return "Please provide your channel_id"
    transcripts = get_all_transcript(user_id,channel_id)
    if not transcripts:
        return "No transcripts found for this channel, please continue with the conversation"
    return transcripts

def get_chatbot_response_agent(query, user_id,channel_id,session_id, history=None):
    if history is None:
        history = {"messages": []}
    print("hIStory",history)
    msg = []
    # Process history messages
    try:
        history_records = get_history(session_id,user_id)
        print("HISTORY_RECORDS",history_records)
        if history_records is None:
            history = {"messages": []}
        if history_records and "messages" in history_records["history"]:
            for message_data in history_records["history"]["messages"]:
                role = message_data['role']
                content = message_data['content']
                if role == 'assistant':
                    msg.append(AIMessage(content=content))
                    history["messages"].append({'role': 'assistant', 'content': content})

                elif role == 'user':
                    msg.append(HumanMessage(content=content))
                    history["messages"].append({'role': 'user', 'content': content})

        else:
            starter_message = "Your AI Assistant, feel free to share anything"
            msg.append(AIMessage(content=starter_message))
            history["messages"].append({'role': 'assistant', 'content': starter_message})
    except Exception as e:
        # Initialize history if get_history returns None
        history = {"messages": []}
        starter_message = "Your AI Assistant, feel free to share anything."
        msg.append(AIMessage(content=starter_message))
        history["messages"].append({'role': 'assistant', 'content': starter_message})
        print(f"Error in getting chat history: {e}")

    msg.append(HumanMessage(content=query))
    history["messages"].append({'role': 'user', 'content': query})


    tool1 = StructuredTool.from_function(get_transcripts)

    tools = [tool1]
    prompt=f"""
        You are a youtuber and the best youtube video script writer, you help people write a svript for a youtube video they ask you , you can copy stype of any youtuber, and the user provide you the transcripts of the video from anyu pupolar youtube channel and will ask you to write a script like that , you have to prepare a script with that similar style of the youtube channel.
        you scripts help make the video pupolar and get millions of views and likes, you are a very famous script writer and you have a lot of clients.
        You are very friendly and you like to talk to your clients and help them with their problems.
        You can tools avaliable to get the transcripts of the youtube channel and you can use the transcripts to write a script for the user.Just copy the style of the script. 
        Confidential: You can use these parameters for using the tool user_id={user_id} and channel_id={channel_id}, just pass values in parameter like this get_transcripts({user_id},{channel_id}) and you will get the transcripts of the youtube channel.
        Make scripts of more than 1500 words.
"""

    message = SystemMessage(content=(prompt))




    prompt = OpenAIFunctionsAgent.create_prompt(
        system_message=message,
        extra_prompt_messages=[MessagesPlaceholder(variable_name="history")],
    )
    # gpt-4-1106-preview
    # gpt-35-turbo-16k
    # gpt-3.5-turbo
    llm = ChatOpenAI(temperature=0.4, streaming=True, model="gpt-3.5-turbo",max_retries=7 )

    agent = OpenAIFunctionsAgent(llm=llm, tools=tools, prompt=prompt)
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        return_intermediate_steps=True,
    )
    print(msg)
   # Append the AI response to the history
    response = agent_executor(
        {
            "input": query,
            "history": msg,
        },
        include_run_info=True,
    )
    history["messages"].append({'role': 'assistant', 'content': response["output"]})

    # Update the user's history in the database
    print("HisTORY_MEssage",history)
    chatDetails = history['messages'][1]['content']
    print(chatDetails)
    update_sess = update_session(user_id,channel_id,chatDetails)
    va =  set_history(session_id, history,user_id)


    return response['output']
