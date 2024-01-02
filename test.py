
import operation


operation.run_nwipe(
    device='/dev/sda',
    verify=operation.Verifies.last,
    method=operation.Methods.dodshort,
    rounds=10,
    log_path='/root/nwipe_log/',
    pdf_report_path='/root/nwipe_log/',
    prng_method=operation.PRNGOption.isaac

)
