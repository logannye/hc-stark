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
    const output = form.querySelector("[data-roi-output]");
    if (!output) return;
    // This worksheet used to subtract the $4,990 annual Guard price and report
    // a purchase decision. Guard is withdrawn and is not sold at any price, so
    // quoting it here would price a product that does not exist. What survives
    // the withdrawal is the only part that was ever customer-owned: the size of
    // the problem itself, which is what decides whether adopting the engine is
    // worth anyone's integration time.
    output.textContent = [
      `Documented annual avoidable cost: ${dollars.format(avoidable)}.`,
      avoidable > 0
        ? "Compare this against the engineering time to adopt the free MIT engine, and validate the same workload and integration boundary before treating it as actionable."
        : "Enter your documented capacity, restart, and delay costs to size the problem.",
    ].join(" ");
  });
})();
