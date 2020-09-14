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