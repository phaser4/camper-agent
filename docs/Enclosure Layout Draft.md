# Enclosure Layout Draft

This is a first-pass physical layout draft for the camper monitor enclosure. It is intentionally conceptual rather than dimension-accurate, so we can agree on placement and serviceability before building a detailed CAD model.

![Enclosure layout draft](/C:/Users/spol/AgentCamper/docs/enclosure-layout-draft.svg)

## Draft intent

The enclosure is a two-piece printed case with a removable lid and a flat mounting base.

The current concept uses:

* A rectangular enclosure approximately `180 x 120 x 45 mm`
* Bottom-mounted standoffs for the DFR0535, SIM7080G HAT, and a small controller/sensor carrier
* A protected backup battery mounted low in the case between the power and modem sections
* Left-side cable entry for camper power and optional wired sensors
* Right-side antenna exits so the LTE and optional GNSS leads stay close to the modem
* A vented wall area near the environmental sensor so temperature and humidity readings are less biased by charger and modem heat

## Placement summary

* **Left bay:** DFR0535 power module, fuse/service wiring entry, and strain-relieved power harness
* **Center-upper bay:** XIAO ESP32-C6 plus SHT40 and MAX17043 on a small carrier or perfboard
* **Center-lower bay:** 1S backup battery with foam retention strap or printed clamp
* **Right bay:** SIM7080G HAT with keep-out space for burst current capacitor and antenna cable bend radius

## Why this arrangement

* The modem stays close to the antenna exits and away from the environmental sensor.
* The charger and camper-input wiring stay grouped at one side of the box.
* The controller remains centrally accessible for USB programming and debugging.
* The battery sits low and central so wiring is short and the mass is balanced.
* The sensor gets its own vented edge rather than sitting above the warm power components.

## Important assumptions

* Dimensions are placeholders until each module is measured directly, including connector overhang and cable bend space.
* The current concept assumes a prototype enclosure, not a gasketed outdoor-rated final housing.
* The XIAO is assumed to be mounted on a small internal carrier board rather than left loose on flying leads.
* The LTE antenna may remain external to the printed box if RF performance is better that way.

## Next CAD pass

The detailed model should lock down:

* Real board outlines and mounting-hole spacing
* Lid fastening method
* Cable-gland sizes and side selection
* USB access strategy for the XIAO
* Battery retention method
* Vent slot pattern near the SHT40
* Antenna bulkhead or pass-through geometry
