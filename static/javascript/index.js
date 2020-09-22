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
    document.getElementById("username_delete").value = username;
    document.getElementById("usernameDeleteVisible").innerHTML = username;
}

/*
 * Function that populates hidden username tag and visible username display in the updateAdminStatusModal
 */
function openUpdateAdminModal(username) {
    document.getElementById("username_admin").value = username;
    document.getElementById("usernameAdminVisible").innerHTML = username;
}

/*
 * Function that populates hidden email tag and visible email display in the deleteUserAccountModal EmailUserModal
 */
function openEmailUserModal(email) {
    document.getElementById("email").value = email;
}

// ---------------------------- Functions for help.js -------------------------------

/**
 * Function to populate the To: field with emails of the admins
 */
function populateAdminEmails(adminEmails) {
    document.getElementById("email").value = adminEmails;
}

// -------------------------- Functions for resources.js -----------------------------

/**
 * Function to show symptoms info
 */
function toggleSymptomsInfo() {
    document.getElementById("preventionInfo").style.display = "none";
    document.getElementById("treatmentInfo").style.display = "none";
    document.getElementById("symptomsInfo").style.display = "block";
}

/**
 * Function to show prevention info
 */
function togglePreventionInfo() {
    document.getElementById("treatmentInfo").style.display = "none";
    document.getElementById("symptomsInfo").style.display = "none";
    document.getElementById("preventionInfo").style.display = "block";
}

/**
 * Function to show treatment info
 */
function toggleTreatmentInfo() {
    document.getElementById("preventionInfo").style.display = "none";
    document.getElementById("symptomsInfo").style.display = "none";
    document.getElementById("treatmentInfo").style.display = "block";
}