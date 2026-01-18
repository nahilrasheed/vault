## steghide
Extract data within images or audios
`steghide embed -cf outerfile.jpg -ef innerfile.txt`
`steghide extract -sf outerfile.txt` 

Using steghide to Hide Sensitive Data in an Image File
`steghide embed -ef secret.txt -cf websploit-logo.jpg`
`steghide extract -sf websploit-logo.jpg -xf extracted_data.txt`


- stegdetect

## Alternate data streams (ADS)
- *windows only*
to store a file inside a file 
`type infile.txt > outfile:infile.txt`

to access the inside file
`notepad outfile.txt:infile.txt`

`dir /r` : to show alternate data streams