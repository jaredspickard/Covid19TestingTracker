This project is a flask web app intended to keep track of member participation in UC Berkeley surveillance testing. This service allows for the reporting of scheduled tests and testing results, as well as offers resources, scheduling help, and even an email service (which notifies members that haven't signed up for testing by Thursday, and notifies admins of who has not signed up for testing for the week on Friday) intended to simplify management.


(FOR IFC PRESIDENTS)

I don't want to pay or be liable for hosting your members' data, so I'm not offering it as a full service, however, you're all more than welcome to use the source code and host it yourselves (though I'd recommend making a HIPAA waiver just to be safe).

There are still a few key things that should be done before deploying this webapp, particularly data encryption. I will update the source code as quickly as I can, and let you guys know once it is complete. 

I plan to make some pretty explicit instructions about configuring the app and deploying it, so I will share that once I complete it as well.

Making this app was a huge learning process for me, so there may be bugs and other issues with it. Feel free to report those to me or reach out with any questions. I have also only hosted it locally so far, so I have no guarantees that it will deploy easily.

If you want a bit of guidance before I can come out with any actual instructions, check out this blog (especially Chapters 4 and 5), as this was the tutorial I used to learn Flask. https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-iv-database