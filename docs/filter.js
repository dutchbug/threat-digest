// Tag filter for the headlines list. The page works fine without JavaScript.
document.querySelectorAll(".filters button").forEach(function (button) {
  button.addEventListener("click", function () {
    var tag = button.getAttribute("data-tag");
    document.querySelectorAll(".filters button").forEach(function (b) {
      b.classList.toggle("active", b === button);
    });
    document.querySelectorAll("#headlines .card").forEach(function (card) {
      var tags = (card.getAttribute("data-tags") || "").split("|");
      card.hidden = tag !== "" && tags.indexOf(tag) === -1;
    });
  });
});
