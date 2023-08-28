###################################################
# Copy file and folder by python
###################################################

import shutil, os

#copy file (src,dst)
shutil.copyfile('src_file_path', 'dst_file_path')

#copy folder (src,dst)
shutil.copytree('src_folder_path', 'dst_folder_path')

#copy file for windows
os.system('copy src_file_path dst_file_path')

