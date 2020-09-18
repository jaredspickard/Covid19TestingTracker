/**
 * Function to toggle which form is visible on the report modal
 * @param {string} name: name indicating the form we wish to view
 */
function toggleReportForm(name) {
    if (name == 'schedule') {
        // Hide the result form, show the schedule form
        document.getElementById("resultForm").style.display = "none";
        document.getElementById("scheduleForm").style.display = "block";
    } else if (name == 'result') {
        // Hide the schedule form, show the result form
        document.getElementById("scheduleForm").style.display = "none";
        document.getElementById("resultForm").style.display = "block";
    }
}

// ---------------------------- Functions for admin.js -------------------------------

/*
 * Function that populates hidden username tag and visible username display in the deleteUserAccountModal
 */
function openDeleteUserModal(username) {
    document.getElementById("username").value = username;
    document.getElementById("usernameVisible").innerHTML = username;
}

/*
 * Function that populates hidden email tag and visible email display in the deleteUserAccountModal EmailUserModal
 */
function openEmailUserModal(email) {
    document.getElementById("email").value = email;
}