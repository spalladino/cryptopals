import os

def resource_path(file):
  return os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../resources/', file)
