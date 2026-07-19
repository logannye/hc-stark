(() => {
  "use strict";

  const form = document.querySelector("[data-roi-form]");
  if (!form) return;

  const readAmount = (selector) => {
    const field = form.querySelector(selector);
    const value = Number.parseFloat(field?.value ?? "0");
    return Number.isFinite(value) && value >= 0 ? value : 0;
  };
  const dollars = new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const capacity = readAmount("[data-roi-capacity]");
    const hours = readAmount("[data-roi-hours]");
    const rate = readAmount("[data-roi-rate]");
    const delay = readAmount("[data-roi-delay]");
    const avoidable = capacity + (hours * rate) + delay;
    const net = avoidable - 4990;
    const output = form.querySelector("[data-roi-output]");
    if (!output) return;
    output.textContent = [
      `Documented annual avoidable cost: ${dollars.format(avoidable)}.`,
      `After the $4,990 annual Guard price: ${dollars.format(net)}.`,
      net > 0
        ? "Validate the same workload and integration boundary before treating this as actionable."
        : "The entered cost does not exceed the annual price.",
    ].join(" ");
  });
})();
