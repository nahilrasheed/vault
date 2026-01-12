Cheatsheet - https://training.github.com/downloads/github-git-cheat-sheet/

# Setup
- install `git`
- config git name and email
- Auth / Connect to GH can be done via:  HTTPS / SSH
## SSH Auth
SSH URLs provide access to a Git repository via SSH, a secure protocol. To use these URLs, you must generate an SSH keypair on your computer and add the **public** key to your account on GitHub. For more information, see [Connecting to GitHub with SSH](https://docs.github.com/en/authentication/connecting-to-github-with-ssh).
- [Generating a new SSH key and adding it to the ssh-agent](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent) 
- [Adding a new SSH key to your GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account) 
- [About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification) .
- [Working with SSH key passphrases](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/working-with-ssh-key-passphrases)

1. Generate SSH key
	- `ssh-keygen -t ed25519 -C "your_email@example.com"`
	- give location to save
	- enter passphrase if needed
2. Adding your SSH key to the ssh-agent
	- Start the ssh-agent in the background. : `eval "$(ssh-agent -s)"`
	- Add your SSH private key to the ssh-agent : `ssh-add ~/.ssh/id_ed25519`
3. Add the SSH public key to your account on GitHub.
	- Copy the SSH public key to your clipboard : `cat ~/.ssh/id_ed25519.pub`
	- Go to Github Settings -> Access ->  SSH and GPG keys.
	- Click New SSH key or Add SSH key.
	- In the "Title" field, add a descriptive label for the new key.
	- Select the type of key, either authentication or signing. For more information about commit signing, see [About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification).
	- In the "Key" field, paste your public key.
	- Click Add SSH key.
	- If prompted, confirm access to your account on GitHub.
4. Test SSH connection
	- ` ssh -T git@github.com`
	- verify fingerprint
	- Then if you get this message : `Hi USERNAME! You've successfully authenticated, but GitHub does not provide shell access.` :: SUCCESS.

---
# Config 
`git config --list`

# Actions
fetch - fetches content in server and  adds to master branch
pull = fetch + merge

to show change history of files
git log --follow -p -- file

# Tips
Add `.patch` to the end of a github commit url to see details about that commit (Including author,author email, commit diffs).
