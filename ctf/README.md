# Note
This folder is supposed to be used for ctf challenges.
Each kernel exploitation challenge can have a dedicated subfolder. 
To run them adjust the `config.ini`, in particular the `arch` field and point the `ctf_dir` to the respective challenge subfolder.
To invoke the ctf runner do the usual steps and then execute `python3 start_kgdb.py --ctf --env <path_to_kernel> <path_to_rootfs>`.

