# Release-blocking legal inputs

`legal/EULA.txt` and `legal/THIRD-PARTY-NOTICES.txt` are canonical public
release inputs, but currently contain explicit blocking markers. Do not approve
the legal gate until both files are final and byte-identical to the private
Guard repository copies.

The owner must provide LN Holdings' exact registered seller name and entity
suffix, formation jurisdiction, public notice address, governing law, exclusive
venue, and legal/privacy/support contacts. The owner must also approve the
subscription, cancellation, refund, update entitlement, license scope,
contractor use, warranty, liability, termination, export/sanctions, privacy,
activation-metadata, and effective-date terms.

The notices must come from the final locked dependency and OCI inventories.
The launch gate hashes these two text files and the normalized public Terms,
Privacy, and Refund Policy bytes for every release class; arbitrary digest
claims cannot approve checkout.
