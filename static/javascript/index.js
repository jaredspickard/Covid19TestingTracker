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
 * Function that populates email in the EmailUserModal
 */
function openEmailUserModal(email) {
    document.getElementById("email").value = email;
}

/*
 * Function that populates the testing history modal with the info passed in
 */
function openTestHistoryModal(name, total, pos, neg, inc, unrep, tests) {
    document.getElementById("user_name").innerHTML = name;
    document.getElementById("total_scheduled").innerHTML = total;
    document.getElementById("total_positive").innerHTML = pos;
    document.getElementById("total_negative").innerHTML = neg;
    document.getElementById("total_inconclusive").innerHTML = inc;
    document.getElementById("total_unreported").innerHTML = unrep;
    var test_list = tests.slice(1,-1).split(',');
    var test_html = "";
    for (var i = 0; i < test_list.length; i++) {
        test_html += "<div class='dropdown-item'>" + test_list[i] + "</div>"
    }
    document.getElementById("test_dates").innerHTML = test_html;
    //document.getElementById("user_name").innerHTML = user_info["name"];
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