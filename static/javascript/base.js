// Get the page to select the appropriate list item (Home or Leaderboard)
$(document).ready(function() {
    // Get the hidden tag storing the representation of the selected page
    var pageLinkID = document.getElementById("selectedLink").value;
    // Set one of the list items to be active
    document.getElementById(pageLinkID).className = "nav-item active";
});