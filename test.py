
import operation


operation.run_nwipe(
    device='/dev/sda',
    verify=operation.Verifies.last,
    method=operation.Methods.dodshort,
    rounds=10,
    log_path='/root/nwipe/',
    pdf_report_path='/root/nwipe/',
    prng_method=operation.PRNGOption.isaac

)
