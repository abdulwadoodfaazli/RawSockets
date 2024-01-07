program_script=rawhttpget
main_program=rawsocket.py

perm:
	chmod 755 $(program_script)
	chmod 755 $(main_program)

all: perm

clean:
	rm -rf __pycache__